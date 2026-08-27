#!/usr/bin/env python3
"""
简易 MySQL 数据库防火墙代理

功能：
  1. TCP 代理：监听 3306，转发到真实 MySQL 3308
  2. 身份提取：从 MySQL 连接属性中解析 firewall_user 字段
  3. SQL 审计：记录每条 SQL 及其执行者
  4. ACL 控制：按用户拦截危险 SQL（DROP/DELETE/TRUNCATE 等）

使用方法：
  1. 启动防火墙：  python3 mysql_firewall.py
  2. 修改应用 JDBC URL 端口为 3306：
     jdbc:mysql://localhost:3306/smart_admin_v3?...
  3. 登录系统后查看防火墙日志，确认 firewall_user 身份已透传
"""

import asyncio
import re
import struct
import logging
import sys

# ==================== 配置 ====================
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 3306          # 防火墙监听端口
MYSQL_HOST  = '127.0.0.1'
MYSQL_PORT  = 3308          # 真实 MySQL 端口

# ACL 规则：firewall_user → 允许/拒绝的 SQL 前缀
# 空 = 监控模式（只记录不拦截）
ACL_RULES = {
    # 示例：禁止 admin 用户执行 DROP/TRUNCATE
    # '1': {
    #     'deny_sql': ['DROP', 'TRUNCATE', 'DELETE FROM'],
    # },
}

LOG_SQL = True               # 是否记录 SQL
# ===============================================

# MySQL 能力标志位
CLIENT_CONNECT_ATTRS   = 0x00200000
CLIENT_PLUGIN_AUTH     = 0x00080000
CLIENT_CONNECT_WITH_DB = 0x00000008

# ANSI 颜色
C_GREEN  = '\033[92m'
C_YELLOW = '\033[93m'
C_RED    = '\033[91m'
C_CYAN   = '\033[96m'
C_RESET  = '\033[0m'

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S',
)
logger = logging.getLogger('Firewall')


# --------------- MySQL 协议解析 ---------------

def read_lenenc_int(data: bytes, offset: int):
    """读取 MySQL 变长整数，返回 (值, 新偏移)"""
    if offset >= len(data):
        return 0, offset
    b = data[offset]
    if b < 0xfb:
        return b, offset + 1
    elif b == 0xfc:
        return struct.unpack_from('<H', data, offset + 1)[0], offset + 3
    elif b == 0xfd:
        val = data[offset+1] | (data[offset+2] << 8) | (data[offset+3] << 16)
        return val, offset + 4
    elif b == 0xfe:
        return struct.unpack_from('<Q', data, offset + 1)[0], offset + 9
    return 0, offset + 1


def read_null_str(data: bytes, offset: int):
    """读取 null 结尾字符串，返回 (字符串, 新偏移)"""
    end = data.find(b'\x00', offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode('utf-8', errors='replace'), end + 1


def parse_handshake_response(payload: bytes) -> dict:
    """
    解析客户端握手响应包，提取 username / database / 连接属性
    """
    offset = 0
    result = {'username': '', 'database': '', 'attrs': {}}

    cap_flags = struct.unpack_from('<I', payload, offset)[0]
    offset += 4      # 能力标志
    offset += 4      # 最大包大小
    offset += 1      # 字符集
    offset += 23     # 保留字段

    result['username'], offset = read_null_str(payload, offset)

    auth_len, offset = read_lenenc_int(payload, offset)
    offset += auth_len

    if cap_flags & CLIENT_CONNECT_WITH_DB and offset < len(payload):
        result['database'], offset = read_null_str(payload, offset)

    if cap_flags & CLIENT_PLUGIN_AUTH and offset < len(payload):
        _, offset = read_null_str(payload, offset)

    if cap_flags & CLIENT_CONNECT_ATTRS and offset < len(payload):
        attrs_len, offset = read_lenenc_int(payload, offset)
        attrs_end = offset + attrs_len
        while offset < attrs_end and offset < len(payload):
            key_len, offset = read_lenenc_int(payload, offset)
            key = payload[offset:offset+key_len].decode('utf-8', errors='replace')
            offset += key_len
            val_len, offset = read_lenenc_int(payload, offset)
            val = payload[offset:offset+val_len].decode('utf-8', errors='replace')
            offset += val_len
            result['attrs'][key] = val

    return result


def build_error_packet(seq: int, code: int, msg: str) -> bytes:
    """构造 MySQL Error 包"""
    payload = b'\xff' + struct.pack('<H', code) + b'#HY000' + msg.encode('utf-8')
    header = struct.pack('<I', len(payload))[:3] + bytes([seq & 0xff])
    return header + payload


async def read_mysql_packet(reader: asyncio.StreamReader) -> bytes:
    """读取一个完整的 MySQL 协议包（4字节头 + 载荷）"""
    header = await reader.readexactly(4)
    length = struct.unpack_from('<I', header, 0)[0] & 0xffffff
    payload = await reader.readexactly(length)
    return header + payload


# --------------- ACL 检查 ---------------

def check_acl(firewall_user: str, sql: str) -> tuple:
    """
    检查 SQL 是否被允许
    返回 (allowed: bool, reason: str)
    """
    if firewall_user not in ACL_RULES:
        return True, '无规则限制'
    rules = ACL_RULES[firewall_user]
    sql_upper = sql.strip().upper()
    for pattern in rules.get('deny_sql', []):
        if sql_upper.startswith(pattern.upper()):
            return False, f'命中拒绝规则: {pattern}'
    allowed = rules.get('allow_sql', [])
    if allowed:
        for pattern in allowed:
            if sql_upper.startswith(pattern.upper()):
                return True, f'命中允许规则: {pattern}'
        return False, '不在允许列表中'
    return True, '无规则限制'


# --------------- 代理核心 ---------------

class FirewallProxy:

    def __init__(self):
        self.conn_counter = 0

    async def handle_client(self, reader, writer):
        self.conn_counter += 1
        conn_id = self.conn_counter
        client_addr = writer.get_extra_info('peername')
        firewall_user = 'unknown'

        try:
            mysql_reader, mysql_writer = await asyncio.open_connection(MYSQL_HOST, MYSQL_PORT)
        except Exception as e:
            logger.error(f'{C_RED}[#{conn_id}] 无法连接 MySQL {MYSQL_HOST}:{MYSQL_PORT}: {e}{C_RESET}')
            writer.close()
            return

        try:
            # 1. 转发服务端握手包
            greeting = await read_mysql_packet(mysql_reader)
            writer.write(greeting)
            await writer.drain()

            # 2. 解析客户端握手响应，提取身份
            hs_response = await read_mysql_packet(reader)
            info = parse_handshake_response(hs_response[4:])
            firewall_user = info['attrs'].get('firewall_user', 'unknown')

            logger.info(
                f'{C_GREEN}[#{conn_id}] 连接建立:{C_RESET} '
                f'db_user={info["username"]}, '
                f'firewall_user={C_CYAN}{firewall_user}{C_RESET}, '
                f'db={info["database"] or "N/A"}, '
                f'from={client_addr}'
            )

            # 打印所有连接属性（调试用）
            for k, v in info['attrs'].items():
                logger.info(f'         属性: {k} = {v}')

            # 转发握手响应到 MySQL
            mysql_writer.write(hs_response)
            await mysql_writer.drain()

            # 3. 双向转发 + SQL 审计
            await asyncio.gather(
                self._forward_client(reader, mysql_writer, writer, conn_id, firewall_user),
                self._forward_server(mysql_reader, writer, conn_id, firewall_user),
            )
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.error(f'{C_RED}[#{conn_id}] 错误: {e}{C_RESET}')
        finally:
            for w in [writer, mysql_writer]:
                try:
                    w.close()
                except Exception:
                    pass
            logger.info(f'{C_YELLOW}[#{conn_id}] 连接关闭 (firewall_user={firewall_user}){C_RESET}')

    async def _forward_client(self, src, mysql_dst, client_dst, conn_id, initial_user):
        """客户端 → MySQL，审计 SQL，跟踪 session 变量"""
        # 使用可变容器跟踪当前连接的用户身份
        # 初始值来自连接属性，后续可通过 SET @firewall_user 更新
        session = {'firewall_user': initial_user}

        try:
            while True:
                packet = await read_mysql_packet(src)
                seq = packet[3]

                # COM_QUERY = 0x03
                if len(packet) > 4 and packet[4] == 0x03:
                    sql = packet[5:].decode('utf-8', errors='replace')
                    current_user = session['firewall_user']

                    # 调试：打印 SQL 的前 60 字节的 hex 和原文，方便排查 Connector/J 是否加注释
                    if 'firewall_user' in sql.lower():
                        logger.info(
                            f'{C_YELLOW}[#{conn_id}] DEBUG SQL hex:{C_RESET} '
                            f'{sql[:60].encode("utf-8").hex()}'
                        )
                        logger.info(
                            f'{C_YELLOW}[#{conn_id}] DEBUG SQL raw:{C_RESET} '
                            f'{repr(sql[:60])}'
                        )

                    # 检测 SET @firewall_user = 'xxx' 语句
                    # 使用宽松匹配：Connector/J 8.x 可能在 SQL 前加注释，或使用 @@session. 前缀
                    m = re.search(
                        r"@+firewall_user\s*=\s*'([^']*)'",
                        sql,
                        re.IGNORECASE,
                    )
                    if m and re.search(r"\bSET\b", sql, re.IGNORECASE):
                        new_user = m.group(1)
                        old_user = session['firewall_user']
                        if old_user != new_user:
                            logger.info(
                                f'{C_GREEN}[#{conn_id}] 身份切换:{C_RESET} '
                                f'{C_YELLOW}{old_user}{C_RESET} → '
                                f'{C_CYAN}{new_user}{C_RESET}'
                            )
                        session['firewall_user'] = new_user
                        # 转发 SET 语句到 MySQL
                        mysql_dst.write(packet)
                        await mysql_dst.drain()
                        continue

                    allowed, reason = check_acl(current_user, sql)

                    if allowed:
                        if LOG_SQL:
                            logger.info(
                                f'{C_CYAN}[#{conn_id}]{C_RESET} '
                                f'QUERY [user={current_user}]: {sql[:200]}'
                            )
                        mysql_dst.write(packet)
                        await mysql_dst.drain()
                    else:
                        logger.warning(
                            f'{C_RED}[#{conn_id}] BLOCKED [user={current_user}] '
                            f'{reason}: {sql[:200]}{C_RESET}'
                        )
                        # 发送错误包给客户端，不转发给 MySQL
                        err = build_error_packet(seq + 1, 1142, f'Firewall: SQL blocked - {reason}')
                        client_dst.write(err)
                        await client_dst.drain()
                else:
                    mysql_dst.write(packet)
                    await mysql_dst.drain()
        except asyncio.IncompleteReadError:
            pass
        except Exception:
            pass

    async def _forward_server(self, src, dst, conn_id, firewall_user):
        """MySQL → 客户端"""
        try:
            while True:
                packet = await read_mysql_packet(src)
                dst.write(packet)
                await dst.drain()
        except asyncio.IncompleteReadError:
            pass
        except Exception:
            pass


# --------------- 启动 ---------------

async def main():
    logger.info(f'{C_GREEN}MySQL 防火墙代理启动{C_RESET}')
    logger.info(f'  监听:   {LISTEN_HOST}:{LISTEN_PORT}')
    logger.info(f'  MySQL:  {MYSQL_HOST}:{MYSQL_PORT}')
    logger.info(f'  SQL审计: {"开启" if LOG_SQL else "关闭"}')
    logger.info(f'  ACL规则: {len(ACL_RULES)} 个用户已配置')
    logger.info(f'')
    logger.info(f'  修改应用 JDBC URL 端口为 {LISTEN_PORT}:')
    logger.info(f'  jdbc:mysql://localhost:{LISTEN_PORT}/smart_admin_v3?...')
    logger.info(f'')

    proxy = FirewallProxy()
    server = await asyncio.start_server(
        proxy.handle_client,
        LISTEN_HOST,
        LISTEN_PORT,
    )
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n防火墙已停止')
        sys.exit(0)
