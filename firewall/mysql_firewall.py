#!/usr/bin/env python3
"""
简易 MySQL 数据库防火墙代理（L2：表级 ACL）

功能：
  1. TCP 代理：监听 3306，转发到真实 MySQL 3308
  2. 身份提取：从 MySQL 连接属性 + SET @firewall_user 会话变量解析当前操作用户
  3. SQL 解析：用 sqlparse 提取 SQL 的操作类型 + 涉及的表
  4. ACL 控制：按 (userId, 表名, 操作类型) 三维矩阵查 t_firewall_acl 表决策，拒绝的 SQL 不转发
  5. SQL 审计：记录每条 SQL 及其执行者
  6. 策略热加载：向进程发送 SIGUSR1 信号即可重新拉取 ACL 策略

使用方法：
  1. 在 MySQL 上执行 firewall/acl_schema.sql 建 t_firewall_acl 表
  2. 安装依赖：pip3 install sqlparse pymysql
  3. 修改下方 ACL_DB_CONFIG 指向你真实的 MySQL（3308）
  4. 启动防火墙：python3 firewall/mysql_firewall.py
  5. 修改应用 JDBC URL 端口为 3306：jdbc:mysql://localhost:3306/smart_admin_v3?...
  6. 修改 ACL 策略后，发送信号热加载：pkill -SIGUSR1 -f mysql_firewall.py
"""

import asyncio
import logging
import re
import signal
import struct
import sys
from functools import lru_cache

import pymysql
import sqlparse
from sqlparse.sql import Identifier, IdentifierList, Parenthesis, Where

# ==================== 配置 ====================
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 3306          # 防火墙监听端口
MYSQL_HOST  = '127.0.0.1'
MYSQL_PORT  = 3308          # 真实 MySQL 端口（应用经防火墙转发到这里）

# ACL 策略数据库连接（用于读取 t_firewall_acl 表，建议用只读账号）
ACL_DB_CONFIG = {
    'host':             '127.0.0.1',
    'port':             3308,
    'user':             'root',
    'password':         'root',
    'database':         'smart_admin_v3',
    'charset':          'utf8mb4',
    'connect_timeout':  5,
}

# 解析失败时的默认行为：True=放行（监控模式），False=拒绝（严格模式）
ALLOW_ON_PARSE_FAIL = True

LOG_SQL = True               # 是否记录每条 SQL
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


# --------------- ACL 策略加载 ---------------

# 内存中的策略缓存：{ user_id: { table_name: set(allowed_ops) } }
# 表名/用户都支持 '*' 通配符
_ACL_CACHE: dict = {}

# 数据资产密级缓存：{ table_name(小写) -> sensitivity_level (1~4) }
_DATA_ASSET_CACHE: dict = {}

# 用户密级缓存：{ user_id -> clearance_level (1~4) }
_USER_CLEARANCE_CACHE: dict = {}

# 标记是否正在加载，防止并发触发
_LOADING_FLAG = False


def load_acl_from_db() -> bool:
    """
    从 t_firewall_acl / t_data_asset / t_user_clearance 表加载策略到内存
    返回是否加载成功
    """
    global _ACL_CACHE, _DATA_ASSET_CACHE, _USER_CLEARANCE_CACHE
    try:
        conn = pymysql.connect(**ACL_DB_CONFIG)
    except Exception as e:
        logger.error(f'{C_RED}加载策略失败：无法连接 MySQL {ACL_DB_CONFIG["host"]}:{ACL_DB_CONFIG["port"]}: {e}{C_RESET}')
        return False
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            # 1. ACL 策略
            cur.execute(
                "SELECT user_id, table_name, allowed_ops FROM t_firewall_acl WHERE enabled = 1"
            )
            acl_rows = cur.fetchall()

            # 2. 数据资产密级
            try:
                cur.execute(
                    "SELECT table_name, sensitivity_level FROM t_data_asset WHERE enabled = 1 AND column_name IS NULL"
                )
                asset_rows = cur.fetchall()
            except Exception as e:
                logger.warning(f'{C_YELLOW}t_data_asset 表查询失败（密级校验将放行所有表）：{e}{C_RESET}')
                asset_rows = []

            # 3. 用户密级
            try:
                cur.execute(
                    "SELECT user_id, clearance_level FROM t_user_clearance WHERE enabled = 1"
                )
                clearance_rows = cur.fetchall()
            except Exception as e:
                logger.warning(f'{C_YELLOW}t_user_clearance 表查询失败（用户密级默认 0=公开）：{e}{C_RESET}')
                clearance_rows = []
    except Exception as e:
        logger.error(f'{C_RED}查询策略表失败：{e}{C_RESET}')
        logger.error('请确认已执行 firewall/acl_schema.sql 和 firewall/clearance_schema.sql')
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # 构建 ACL 缓存
    new_acl: dict = {}
    for row in acl_rows:
        uid = row['user_id'].strip()
        tbl = row['table_name'].strip()
        ops_raw = (row['allowed_ops'] or '').strip().upper()
        ops = {o.strip() for o in ops_raw.split(',') if o.strip()}
        new_acl.setdefault(uid, {})[tbl] = ops
    _ACL_CACHE = new_acl

    # 构建数据资产密级缓存（key 全部小写，方便匹配）
    new_asset: dict = {}
    for row in asset_rows:
        tbl = (row['table_name'] or '').strip().lower()
        if tbl:
            new_asset[tbl] = int(row['sensitivity_level'])
    _DATA_ASSET_CACHE = new_asset

    # 构建用户密级缓存
    new_clearance: dict = {}
    for row in clearance_rows:
        uid = (row['user_id'] or '').strip()
        if uid:
            new_clearance[uid] = int(row['clearance_level'])
    _USER_CLEARANCE_CACHE = new_clearance

    logger.info(
        f'{C_GREEN}策略已加载：ACL {len(acl_rows)} 条 / 资产密级 {len(asset_rows)} 条 / 用户密级 {len(clearance_rows)} 条{C_RESET}'
    )
    for uid, tables in new_acl.items():
        logger.info(f'         ACL  | {uid} | {list(tables.keys())}')
    if new_asset:
        logger.info(f'         资产 | {dict(list(new_asset.items())[:10])}{"..." if len(new_asset) > 10 else ""}')
    if new_clearance:
        logger.info(f'         用户 | {new_clearance}')
    return True


def _handle_sigusr1(signum, frame):
    """SIGUSR1 信号：热重新加载 ACL 策略"""
    global _LOADING_FLAG
    if _LOADING_FLAG:
        return
    _LOADING_FLAG = True
    logger.info(f'{C_YELLOW}收到 SIGUSR1，重新加载 ACL 策略...{C_RESET}')
    try:
        load_acl_from_db()
    finally:
        _LOADING_FLAG = False


# --------------- SQL 解析 ---------------

# DDL 关键字集合
_DDL_KEYWORDS = {'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'RENAME'}


@lru_cache(maxsize=4096)
def parse_sql(sql: str):
    """
    解析 SQL，返回 (operation, tables)
    operation: SELECT/INSERT/UPDATE/DELETE/DDL/OTHER
    tables: set[str]，SQL 涉及的表名集合（小写）
    """
    sql_stripped = sql.strip().rstrip(';').strip()
    if not sql_stripped:
        return 'OTHER', set()

    first_token = sql_stripped.split(None, 1)[0].upper()
    if first_token in _DDL_KEYWORDS:
        op = 'DDL'
    elif first_token in ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'REPLACE'):
        op = first_token
    elif first_token == 'SET':
        # SET @firewall_user 等会话变量，不算业务 SQL
        return 'SET', set()
    elif first_token in ('SHOW', 'EXPLAIN', 'DESC', 'DESCRIBE', 'USE', 'BEGIN', 'COMMIT', 'ROLLBACK', 'START', 'SAVEPOINT'):
        return 'META', set()
    else:
        op = 'OTHER'

    tables = set()
    try:
        parsed = sqlparse.parse(sql_stripped)
        if not parsed:
            return op, tables
        stmt = parsed[0]
        _collect_identifiers(stmt, tables, first_token)
    except Exception as e:
        logger.debug(f'parse_sql 解析失败，继续按空表处理：{e}')

    return op, {t.lower() for t in tables}


def _collect_identifiers(stmt, tables: set, first_token: str):
    """从 sqlparse Statement 中递归收集表名"""
    for tok in stmt.tokens:
        if isinstance(tok, IdentifierList):
            for t in tok.get_identifiers():
                _collect_one(t, tables)
        elif isinstance(tok, Identifier):
            _collect_one(tok, tables)
        elif isinstance(tok, Parenthesis):
            # 子查询：递归
            for sub in tok.tokens:
                if hasattr(sub, 'tokens'):
                    _collect_identifiers(sub, tables, first_token)
        elif tok.ttype is sqlparse.tokens.Keyword and tok.value.upper() == 'FROM':
            pass  # sqlparse 的扁平遍历已经处理过 FROM 后的 Identifier
        # Where 子句可能有 JOIN ... ON，递归
        elif isinstance(tok, Where):
            for sub in tok.tokens:
                if hasattr(sub, 'tokens'):
                    _collect_identifiers(sub, tables, first_token)


def _collect_one(tok, tables: set):
    """处理单个 Identifier，提取表名（去掉 schema 前缀和别名）"""
    name = tok.get_real_name() if hasattr(tok, 'get_real_name') else str(tok)
    if name:
        # 去掉反引号
        name = name.strip('`').split()[0]
        if name and not name.startswith('('):
            tables.add(name)


# --------------- ACL 决策 ---------------

def check_table_acl(user: str, op: str, tables: set) -> tuple:
    """
    根据 (userId, 操作类型, 表集合) 决策
    返回 (allowed: bool, reason: str)
    """
    # SET / META 类 SQL 不受 ACL 限制
    if op in ('SET', 'META', 'OTHER'):
        return True, f'{op} 不受 ACL 限制'

    if not tables:
        # 无法解析出表名，按配置决策
        return ALLOW_ON_PARSE_FAIL, '无法解析表名，按 ALLOW_ON_PARSE_FAIL 决策'

    user_rules = _ACL_CACHE.get(user)
    if user_rules is None:
        # 用户没精确匹配，找通配符 '*'
        user_rules = _ACL_CACHE.get('*')
    if user_rules is None:
        return False, f'用户 {user} 不在 ACL 白名单'

    for tbl in tables:
        # 1. 精确表名匹配
        allowed_ops = user_rules.get(tbl)
        # 2. 表名通配符
        if allowed_ops is None and '*' in user_rules:
            allowed_ops = user_rules['*']
        if allowed_ops is None:
            return False, f'用户 {user} 无权访问表 {tbl}'
        if 'ALL' not in allowed_ops and op not in allowed_ops:
            return False, f'用户 {user} 对 {tbl} 无 {op} 权限（仅 {",".join(sorted(allowed_ops))}）'

    return True, 'OK'


# --------------- 密级校验 ---------------

# 找不到用户密级时的默认 clearance
_DEFAULT_USER_CLEARANCE = 1


def _get_user_clearance(user: str) -> int:
    """获取用户密级，支持通配符回退"""
    if not user:
        user = '*'
    if user in _USER_CLEARANCE_CACHE:
        return _USER_CLEARANCE_CACHE[user]
    if '*' in _USER_CLEARANCE_CACHE:
        return _USER_CLEARANCE_CACHE['*']
    return _DEFAULT_USER_CLEARANCE


def check_clearance(user: str, tables: set) -> tuple:
    """
    密级校验：user_clearance >= max(table.sensitivity_level)
    返回 (allowed: bool, reason: str)
    """
    if not tables:
        return True, '无表，跳过密级校验'

    user_level = _get_user_clearance(user)

    # 找出本次 SQL 涉及的最高密级
    max_level = 0
    miss_tables = []
    for tbl in tables:
        level = _DATA_ASSET_CACHE.get(tbl)
        if level is None:
            # 未标记密级的表视为 L1（公开），避免业务表全被拦
            level = 1
            miss_tables.append(tbl)
        if level > max_level:
            max_level = level

    if user_level >= max_level:
        return True, f'用户密级 {user_level} >= 表密级 {max_level}'

    return False, (
        f'用户 {user} 密级 {user_level} 不足以访问密级 {max_level} 的表 '
        f'(需 >= {max_level})'
    )


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

            for k, v in info['attrs'].items():
                logger.info(f'         属性: {k} = {v}')

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
        """客户端 → MySQL，审计 SQL，跟踪 session 变量，按 ACL 决策"""
        session = {'firewall_user': initial_user}

        try:
            while True:
                packet = await read_mysql_packet(src)
                seq = packet[3]

                # COM_QUERY = 0x03
                if len(packet) > 4 and packet[4] == 0x03:
                    sql = packet[5:].decode('utf-8', errors='replace')
                    current_user = session['firewall_user']

                    # 检测 SET @firewall_user = 'xxx' 语句，更新会话身份
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
                        mysql_dst.write(packet)
                        await mysql_dst.drain()
                        continue

                    # L2 表级 ACL 决策
                    op, tables = parse_sql(sql)
                    allowed, reason = check_table_acl(current_user, op, tables)

                    # 密级校验（仅在 ACL 通过后做）
                    if allowed and tables:
                        allowed, reason = check_clearance(current_user, tables)

                    if allowed:
                        if LOG_SQL:
                            logger.info(
                                f'{C_CYAN}[#{conn_id}]{C_RESET} '
                                f'QUERY [user={current_user}] [{op}/{",".join(sorted(tables)) or "-"}]: {sql[:200]}'
                            )
                        mysql_dst.write(packet)
                        await mysql_dst.drain()
                    else:
                        logger.warning(
                            f'{C_RED}[#{conn_id}] BLOCKED [user={current_user}] '
                            f'[{op}/{",".join(sorted(tables))}] {reason}: {sql[:200]}{C_RESET}'
                        )
                        err = build_error_packet(
                            seq + 1, 1142,
                            f'Firewall: SQL blocked - {reason}'
                        )
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
    logger.info(f'{C_GREEN}MySQL 数据库防火墙代理启动 (L2 表级 ACL){C_RESET}')
    logger.info(f'  监听:   {LISTEN_HOST}:{LISTEN_PORT}')
    logger.info(f'  MySQL:  {MYSQL_HOST}:{MYSQL_PORT}')
    logger.info(f'  ACL DB: {ACL_DB_CONFIG["host"]}:{ACL_DB_CONFIG["port"]}/{ACL_DB_CONFIG["database"]}')
    logger.info(f'  SQL审计: {"开启" if LOG_SQL else "关闭"}')
    logger.info('')

    # 加载 ACL 策略
    if not load_acl_from_db():
        logger.warning(
            f'{C_YELLOW}ACL 策略加载失败，将以"放行模式"启动（不拦截，仅审计）{C_RESET}'
        )
    logger.info('')

    # 注册 SIGUSR1 热加载
    try:
        signal.signal(signal.SIGUSR1, _handle_sigusr1)
        logger.info('  热加载: 已注册，发送 SIGUSR1 重新加载 ACL（pkill -SIGUSR1 -f mysql_firewall.py）')
    except Exception as e:
        logger.warning(f'  无法注册 SIGUSR1：{e}')

    logger.info('')
    logger.info(f'  修改应用 JDBC URL 端口为 {LISTEN_PORT}:')
    logger.info(f'  jdbc:mysql://localhost:{LISTEN_PORT}/smart_admin_v3?...')
    logger.info('')

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
