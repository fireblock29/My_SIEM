<?php
// Simple vuln demo — NE PAS mettre en prod.
if (isset($_GET['exploit'])) {
    $val = $_GET['exploit'];
    echo "Processing: " . htmlentities($val);
} else {
    echo "Welcome to vulnerable webapp";
}
?>
