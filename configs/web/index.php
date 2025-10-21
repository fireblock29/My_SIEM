<?php
if (isset($_GET['exploit'])) {
    $val = $_GET['exploit'];
    echo "Processing: " . htmlentities($val);
} else {
    echo "Welcome to vulnerable webapp";
}
?>
