<?php
// vuln.php (phiên bản an toàn)
$mysqli = new mysqli('localhost', 'root', '', 'app_web1');
if ($mysqli->connect_errno) {
    // dev: bạn có thể echo lỗi; production: log lỗi
    die("Lỗi kết nối DB");
}

// Lấy param an toàn
$id = $_GET['id'] ?? '';

// Validate: id phải là số (chuỗi chỉ gồm chữ số)
if ($id === '' || !ctype_digit($id)) {
    http_response_code(400);
    echo "Tham số id không hợp lệ.";
    exit;
}

// Prepared statement để tránh SQL injection
$stmt = $mysqli->prepare("SELECT id, name FROM users WHERE id = ?");
if ($stmt === false) {
    error_log("Prepare failed: " . $mysqli->error);
    die("Lỗi nội bộ.");
}

$intId = (int)$id;
$stmt->bind_param("i", $intId);
$stmt->execute();

$result = $stmt->get_result();
if ($result === false) {
    error_log("Get result failed: " . $stmt->error);
    die("Lỗi truy vấn.");
}

if ($result->num_rows === 0) {
    echo "Không tìm thấy user.";
} else {
    while ($row = $result->fetch_assoc()) {
        echo "User: " . htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8') . "<br>";
    }
}

$stmt->close();
$mysqli->close();