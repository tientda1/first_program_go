# gologin — bài tập login với Go

Bài toán: đăng nhập có rate limit, dùng 2 bảng `users` + `sessions`, mật khẩu hash bcrypt cost 12,
kiểm tra tài khoản bị xoá / bị khoá, và trả về đúng các trường cần thiết.

## Chạy thử

```bash
# 1. Bật Postgres (Docker) — file migrations tự chạy ở lần khởi tạo đầu tiên
docker compose up -d

# nếu DB đã tồn tại từ trước, chạy migration tay:
# docker exec -i gologin-postgres psql -U postgres -d gologin < migrations/001_init.sql

# 2. Tạo user mẫu (alice / Password123!)
go run ./cmd/seed

# 3. Chạy server
go run ./cmd/server

# 4. Test
curl -i -X POST localhost:8080/api/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"alice","password":"Password123!"}'

curl -i localhost:8080/api/me -H 'Authorization: Bearer <token>'
curl -i -X POST localhost:8080/api/logout -H 'Authorization: Bearer <token>'
```

Cấu hình qua biến môi trường, xem `.env.example`.

## Cấu trúc

```
cmd/server        # main: wiring + graceful shutdown + job dọn session
cmd/seed          # tạo user mẫu
migrations        # DDL + index
internal/
  config          # đọc env
  db              # mở pool pgx (database/sql)
  httpx           # JSON/error response, lấy IP, đọc bearer token
  model           # User, Session, PublicUser
  repository      # SQL thuần
  service         # logic login (nơi chứa toàn bộ quy tắc nghiệp vụ)
  middleware      # rate limit theo IP, xác thực session
  handler         # HTTP: login / logout / me
  ratelimit       # token bucket in-memory, mỗi key một bucket
```

## Luồng login (đúng thứ tự)

1. **Rate limit theo IP** (middleware) — chặn trước khi parse body / chạm DB.
2. **Rate limit theo username** (trong handler) — chặn brute force nhắm vào 1 tài khoản từ nhiều IP.
3. Tìm user theo `username = $1 OR email = lower($1)`.
4. **Không tìm thấy** → chạy một phép bcrypt "giả" rồi trả `invalid_credentials` để thời gian phản hồi
   không tiết lộ user có tồn tại hay không.
5. **Kiểm tra xoá**: `deleted_at IS NOT NULL` → `403 account_deleted`.
6. **Kiểm tra khoá**: `status = 0` (admin khoá) hoặc `locked_until > now()` (khoá do sai quá nhiều lần)
   → `423 account_locked`.
7. `bcrypt.CompareHashAndPassword`. Sai → `failed_attempts + 1`, đủ ngưỡng thì set `locked_until`,
   trả `401 invalid_credentials`.
8. Đúng → reset `failed_attempts`/`locked_until`, sinh token, lưu **hash của token** vào `sessions`.
9. Trả về `id, username, email, created_at` + token. Không bao giờ trả `password_hash`, `deleted_at`,
   `failed_attempts`.

Thứ tự này quan trọng: kiểm tra xoá/khoá **trước** khi so mật khẩu, để tài khoản đã khoá không thể
"thăm dò" mật khẩu đúng/sai qua thời gian phản hồi.

## Index và lý do

| Index | Vì sao |
|---|---|
| `ux_users_username` UNIQUE | `username` là điểm vào của login. Vừa tăng tốc tra cứu vừa ép không cho 2 user trùng tên. |
| `ux_users_email_lower` UNIQUE | Cho phép login bằng email. Đánh trên `lower(email)` nên `Alice@Mail.com` và `alice@mail.com` là cùng một tài khoản — nếu không, kẻ tấn công chỉ cần đổi hoa/thường để lách ràng buộc duy nhất. |
| `ux_sessions_token_hash` UNIQUE | **Index nóng nhất hệ thống.** Mọi request đã đăng nhập đều tra session theo `token_hash`. Thiếu nó là full table scan mỗi request. UNIQUE để 1 token không map sang 2 session. |
| `ix_sessions_user_id` | Phục vụ "đăng xuất mọi thiết bị", liệt kê session của 1 user, và tăng tốc `ON DELETE CASCADE`. |
| `ix_sessions_expires_at` | Job định kỳ `DELETE ... WHERE expires_at < now()`; không index thì mỗi lần dọn phải quét cả bảng sessions. |

Nguyên tắc: **chỉ index cột thực sự xuất hiện trong `WHERE` / `JOIN` / `ORDER BY`**. Các cột như
`status`, `user_agent` có độ chọn lọc thấp (low cardinality) nên index hầu như vô ích, chỉ tốn chỗ
và làm chậm `INSERT`/`UPDATE`.

Kiểm chứng bằng `EXPLAIN ANALYZE`:

```sql
EXPLAIN ANALYZE SELECT id, username FROM users WHERE username = 'alice';
--  Index Scan using ux_users_username on users  (cost=0.15..8.17 rows=1 ...)

EXPLAIN ANALYZE SELECT id, user_id FROM sessions WHERE token_hash = repeat('a', 64);
--  Index Scan using ux_sessions_token_hash on sessions  (cost=0.15..8.17 rows=1 ...)

-- Nếu bỏ index, kế hoạch đổi thành Seq Scan và cost tăng theo số dòng của bảng.
```

## Các quyết định thiết kế (trade-off)

**Vì sao lưu `token_hash` chứ không lưu token gốc?**
DB bị rò rỉ thì kẻ tấn công không dùng được session nào. Token gốc chỉ tồn tại ở client. Token 32 byte
random + SHA-256 là đủ vì token đã có entropy cao, không cần bcrypt (bcrypt chỉ cần cho mật khẩu do
con người chọn — vốn ít entropy và dễ đoán).

**Vì sao bcrypt cost 12?**
Cost là log2 số vòng lặp: 12 nghĩa là 2^12 = 4096 vòng. Mỗi lần tăng 1 cost làm thời gian hash gấp đôi.
Bcrypt cố tình chậm để brute force mật khẩu trở nên đắt; 12 là điểm cân bằng hợp lý giữa an toàn và
độ trễ đăng nhập (vài trăm ms). Đây là lý do **không** tự viết "12 vòng SHA" — SHA nhanh, chạy 12 vòng
vẫn nhanh, nên vô nghĩa trước GPU. Salt được bcrypt sinh và nhúng sẵn trong chuỗi hash.

**Vì sao `status` và `locked_until` tách rời?**
`status = 0` là khoá do admin/quản trị (không tự hết). `locked_until` là khoá tạm do sai mật khẩu quá
nhiều lần — tự mở khi hết hạn. Gộp chung một cột sẽ khiến việc "tự mở khoá sau 15 phút" đè lên quyết
định khoá của admin.

**Rate limit in-memory token bucket:**
`golang.org/x/time/rate` cho mỗi key một bucket. Ưu: không cần Redis, dễ đọc. Nhược: chỉ đúng khi
chạy 1 instance — nhiều instance thì mỗi instance đếm riêng, giới hạn thực tế bị nhân lên. Production
nhiều instance phải chuyển sang Redis. Cũng phải có `StartJanitor` để xoá bucket không còn dùng, nếu
không map sẽ phình mãi theo số key.

**Không tin `X-Forwarded-For`:**
Header này do client tự gửi, tin nó là kẻ tấn công chỉ cần đổi header để vượt rate limit. Code chỉ lấy
`RemoteAddr`. Nếu chạy sau reverse proxy thì phải cấu hình danh sách IP proxy tin cậy mới được đọc XFF.

**Vì sao trả về lỗi khác nhau cho `account_deleted` / `account_locked`?**
Theo yêu cầu bài. Nhưng cần biết đây là **đánh đổi**: nó cho phép kẻ tấn công dò xem một email có tồn
tại trong hệ thống hay không (user enumeration). Hệ thống thật thường trả về cùng một lỗi chung cho mọi
trường hợp thất bại. Còn với "sai tài khoản" và "sai mật khẩu", code đã gộp chung thành
`invalid_credentials`.

**Soft delete (`deleted_at`) vs xoá cứng:**
Giữ dòng lại để không mất dấu vết (audit, hoàn tác, khoá người dùng nhưng giữ lịch sử). Đổi lại mọi
truy vấn login phải nhớ `deleted_at IS NULL`, nếu quên là user đã xoá vẫn đăng nhập được.

**Vì sao service dùng interface (`UserStore`, `SessionStore`)?**
Để test được toàn bộ luồng login (kể cả các nhánh xoá/khoá) mà không cần dựng Postgres. Repository thật
đã thoả mãn interface nên `main.go` không đổi.

## Test

```bash
go test ./...
```

- `internal/service`: happy path, sai mật khẩu (có ghi nhận failed attempt), user không tồn tại
  (không lộ thông tin), tài khoản đã xoá, tài khoản bị khoá tạm, tài khoản bị admin khoá, và vòng
  login → authenticate → logout.
- `internal/ratelimit`: cho qua trong burst rồi chặn, mỗi key một bucket riêng, token hồi theo thời
  gian, janitor dọn bucket rảnh.

## Còn thiếu nếu muốn lên production

- Chuyển rate limit sang Redis để đúng khi chạy nhiều instance.
- Ghi log/audit cho sự kiện login thất bại.
- CSRF token nếu dùng cookie cho state-changing request.
- HTTPS + `Secure: true` cho cookie (tham số `secureCookie` trong `main.go` đang để `false` cho local).
