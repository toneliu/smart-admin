-- ======================================================================
-- 数据防火墙 - 数据密级与用户密级表（阶段 2）
-- 配合 firewall/mysql_firewall.py 的密级校验引擎使用
--
-- 密级体系（参考 GB/T 35273 个人信息安全规范 + 通用数据分类分级）：
--   L1 = 公开      （可对外发布，如 t_role 角色定义）
--   L2 = 内部      （员工可见，如 t_order 订单）
--   L3 = 机密      （仅授权岗位可见，如 t_employee 员工薪资）
--   L4 = 绝密      （仅核心管理员可见，如 t_audit_log 安全审计）
--
-- 校验规则：user_clearance_level >= max(table.sensitivity_level)
--   不够则拦截，SQL 不会到达真实 MySQL
-- ======================================================================

-- ---------------------------------------------------------------------
-- 1. 数据资产密级表：标记每张表/每个字段的密级
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `t_data_asset` (
  `id`               bigint        NOT NULL AUTO_INCREMENT              COMMENT '主键',
  `table_name`       varchar(128)  NOT NULL                             COMMENT '表名',
  `column_name`      varchar(128)  DEFAULT NULL                         COMMENT '字段名；NULL 表示整表密级。当前阶段防火墙按表级校验，字段级保留以便阶段4脱敏使用',
  `sensitivity_level` tinyint      NOT NULL                              COMMENT '密级：1=L1公开 2=L2内部 3=L3机密 4=L4绝密',
  `enabled`          tinyint      NOT NULL DEFAULT 1                   COMMENT '是否启用：1=启用 0=禁用',
  `remark`            varchar(255) DEFAULT NULL                         COMMENT '备注',
  `create_time`       datetime     NOT NULL DEFAULT CURRENT_TIMESTAMP   COMMENT '创建时间',
  `update_time`       datetime     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_table_col` (`table_name`, `column_name`),
  KEY `idx_table` (`table_name`),
  KEY `idx_enabled` (`enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='数据资产密级表';

-- ---------------------------------------------------------------------
-- 2. 用户密级表：标记每个 userId 的 clearance 等级
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `t_user_clearance` (
  `id`               bigint        NOT NULL AUTO_INCREMENT              COMMENT '主键',
  `user_id`          varchar(64)   NOT NULL                             COMMENT '用户ID；* 表示通配符（所有未精确匹配的用户）',
  `clearance_level`  tinyint       NOT NULL                              COMMENT '用户密级：1~4，需 >= 表的 sensitivity_level 才能访问',
  `enabled`          tinyint       NOT NULL DEFAULT 1                   COMMENT '是否启用：1=启用 0=禁用',
  `remark`           varchar(255)  DEFAULT NULL                         COMMENT '备注',
  `create_time`      datetime      NOT NULL DEFAULT CURRENT_TIMESTAMP   COMMENT '创建时间',
  `update_time`      datetime      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_user` (`user_id`),
  KEY `idx_enabled` (`enabled`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户密级表';

-- ---------------------------------------------------------------------
-- 3. 示例数据：数据资产密级
-- ---------------------------------------------------------------------
INSERT INTO `t_data_asset` (`table_name`, `column_name`, `sensitivity_level`, `remark`) VALUES
  -- L1 公开
  ('t_role',           NULL, 1, '角色定义表 - 公开'),
  ('t_menu',           NULL, 1, '菜单表 - 公开'),
  ('t_file',           NULL, 1, '文件元数据 - 公开'),
  -- L2 内部
  ('t_order',          NULL, 2, '订单表 - 内部'),
  ('t_department',     NULL, 2, '部门表 - 内部'),
  ('t_login_fail',     NULL, 2, '登录失败记录 - 内部'),
  -- L3 机密
  ('t_employee',       NULL, 3, '员工表 - 机密（含薪资/身份证/手机号）'),
  ('t_employee_dept',  NULL, 3, '员工部门关系 - 机密'),
  -- L4 绝密
  ('t_firewall_acl',   NULL, 4, '防火墙 ACL 策略 - 绝密'),
  ('t_data_asset',     NULL, 4, '数据资产密级 - 绝密'),
  ('t_user_clearance', NULL, 4, '用户密级 - 绝密');

-- ---------------------------------------------------------------------
-- 4. 示例数据：用户密级
-- ---------------------------------------------------------------------
INSERT INTO `t_user_clearance` (`user_id`, `clearance_level`, `remark`) VALUES
  ('1', 4, 'admin - 绝密级，可访问所有表'),
  ('2', 3, 'hr - 机密级，可看员工不可看审计'),
  ('3', 2, '普通员工 - 内部级，可看订单不可看员工'),
  ('*', 1, '默认 - 公开级，仅可看 L1 表');
