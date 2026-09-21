CREATE TABLE users (
    id              BIGSERIAL    PRIMARY KEY,
    username        VARCHAR(50)  NOT NULL,
    email           VARCHAR(255) NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    status          SMALLINT     NOT NULL DEFAULT 1,
    failed_attempts INTEGER      NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT ck_users_status CHECK (status IN (0, 1))
);

-- ux_users_username: username là điểm vào của luồng login (WHERE username = $1).
-- Index này vừa tăng tốc tra cứu vừa ép ràng buộc duy nhất (không cho 2 user trùng tên).
CREATE UNIQUE INDEX ux_users_username ON users (username);

-- ux_users_email_lower: cho phép login bằng email. Đánh trên lower(email) để
-- "Alice@Mail.com" và "alice@mail.com" là cùng một tài khoản, tránh bypass bằng cách đổi hoa/thường.
CREATE UNIQUE INDEX ux_users_email_lower ON users (lower(email));

CREATE TABLE sessions (
    id         UUID        PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash CHAR(64)    NOT NULL,
    ip         VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ux_sessions_token_hash: mọi request đã đăng nhập đều tra session theo token_hash.
-- Đây là truy vấn nóng nhất hệ thống, thiếu index này là full table scan mỗi request.
-- Duy nhất để một token không thể map sang 2 session.
CREATE UNIQUE INDEX ux_sessions_token_hash ON sessions (token_hash);

-- ix_sessions_user_id: phục vụ "đăng xuất mọi thiết bị", liệt kê session của 1 user,
-- và tăng tốc ON DELETE CASCADE khi xoá user.
CREATE INDEX ix_sessions_user_id ON sessions (user_id);

-- ix_sessions_expires_at: job định kỳ xoá session hết hạn (WHERE expires_at < now()).
CREATE INDEX ix_sessions_expires_at ON sessions (expires_at);
