-- ======================================================================
-- 数据库防火墙 ACL 策略表
-- 由 firewall/mysql_firewall.py 在启动时加载到内存，用于按用户ID做表级权限控制
-- 修改策略后，向防火墙进程发送 SIGUSR1 信号即可热加载：
--   pkill -SIGUSR1 -f mysql_firewall.py
-- 或重启防火墙进程
-- ======================================================================

CREATE TABLE IF NOT EXISTS `t_firewall_acl` (
  `id`          bigint        NOT NULL AUTO_INCREMENT              COMMENT '主键',
  `user_id`     varchar(64)   NOT NULL                             COMMENT '用户ID，对应 SET @firewall_user 的值；* 表示通配符（匹配所有未精确匹配的用户）',
  `table_name`  varchar(128)  NOT NULL                             COMMENT '表名；* 表示通配符（匹配所有未精确匹配的表）',
  `allowed_ops` varchar(256)  NOT NULL DEFAULT 'ALL'               COMMENT '允许的操作，逗号分隔：SELECT,INSERT,UPDATE,DELETE,DDL,ALL；ALL 表示全部',
  `enabled`     tinyint       NOT NULL DEFAULT 1                   COMMENT '是否启用：1=启用 0=禁用',
  `remark`      varchar(255)  DEFAULT NULL                         COMMENT '备注',
  `create_time` datetime      NOT NULL DEFAULT CURRENT_TIMESTAMP   COMMENT '创建时间',
  `update_time` datetime      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user_table` (`user_id`, `table_name`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_enabled` (`enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='数据库防火墙 ACL 策略表';

-- 示例策略（按需调整）：
-- admin (userId=1)            全表全操作
-- hr (userId=2)               t_employee 只读+更新；t_department 全操作；其他表禁止
-- 普通员工 (userId=3)         全表只读
-- * (所有未匹配的用户)         默认全表只读，禁止 DDL
INSERT INTO `t_firewall_acl` (`user_id`, `table_name`, `allowed_ops`, `remark`) VALUES
  ('1', '*',            'ALL',                'admin 全表全操作'),
  ('2', 't_employee',  'SELECT,UPDATE',      'hr 只读+更新员工'),
  ('2', 't_department', 'ALL',                'hr 全操作部门'),
  ('3', '*',            'SELECT',             '普通员工只读'),
  ('*', '*',            'SELECT,INSERT,UPDATE,DELETE', '默认：允许 DML，禁止 DDL');
