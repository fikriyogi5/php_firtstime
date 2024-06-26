<?php
date_default_timezone_set("Asia/Jakarta");
$key = "vector";
function maskMiddleDigits($string) {
    // Check if the provided string is not empty
        if (!empty($string)) {
            // Ensure the string length is at least 12 characters
            if (strlen($string) >= 12) {
                // Extract the first 6 characters (before masking)
                $prefix = substr($string, 0, 6);
                // Extract the last 3 characters (after masking)
                $suffix = substr($string, -3);
                // Create a mask of asterisks (*) with the same length as the middle digits
                $mask = str_repeat('*', 3);
                // Combine the prefix, mask, and suffix to form the masked string
                $maskedstring = $prefix . $mask . $suffix;
                return $maskedstring;
            }
        }
        // Return the original string if it's empty or too short to be masked
        return $string;
}

function tampilkanGambar($mhs)
{
    if (!empty($mhs['gambar'])) {
        // Gunakan gambar yang ada jika tersedia
        return $mhs['gambar'];
    } else {
        // Gunakan gambar default berdasarkan jenis kelamin jika tidak ada gambar
        $jenisKelamin = $mhs['jenis_kelamin']; // Ganti dengan nama kolom yang sesuai
        $gambarDefault = ($jenisKelamin == 'L') ? 'man.png' : 'woman.png';

        return $gambarDefault;
    }
}

function getUmurWarga($tanggal_lahir) {
    // Konversi tanggal lahir ke dalam objek DateTime
    $tgl_lahir = new DateTime($tanggal_lahir);
    // Objek DateTime untuk tanggal saat ini
    $tanggal_sekarang = new DateTime();
    // Hitung selisih tahun
    $selisih = $tgl_lahir->diff($tanggal_sekarang);
    // Ambil tahun dari selisih
    $umur = $selisih->y;
    return $umur;
}
function potongTeks($teks, $panjang = 100) {
    if (strlen($teks) > $panjang) {
        $teks = substr($teks, 0, $panjang); // Potong teks menjadi 100 karakter
        $teks = substr($teks, 0, strrpos($teks, ' ')); // Pastikan tidak memotong kata di tengah
        $teks .= '...'; // Tambahkan "..." di akhir teks
    }
    return $teks;
}
function generateHeader($headerOptions) {
    $title = $headerOptions['title'];
    $header_menu = $headerOptions['header_menu'];
    $header_title = $headerOptions['header_title'];
    $link_back = $headerOptions['link_back'];
    $icon = $headerOptions['icon'];
    $footer_menu = $headerOptions['footer_menu'];
    $header_style = $headerOptions['header_style'];

    $html = '<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="viewport" content="width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, viewport-fit=cover"/>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"/>
    <link rel="stylesheet" type="text/css" href="bootstrap.css">
    <script src="scripts/jquery-3.6.0.min.js"></script>
    <script type="text/javascript" src="scripts/bootstrap.min.js"></script>
    <script type="text/javascript" src="scripts/custom.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery.touchswipe/1.6.19/jquery.touchSwipe.min.js">
    </script>
    <title>' . $title . '</title>
</head>
<body class="theme-light" data-highlight="highlight-red" data-gradient="body-default">

<div id="page">';
    if ($header_menu == 1) {
        $html .= '<div class="header header-fixed header-logo-center" style="transform: translateX(0px);">
            <a href="index.php" class="header-title">' . $header_title . '</a>
            <a href="' . $link_back . '" data-menu="menu-sidebar-left-4" class="header-icon header-icon-1">
                <i class="fas ' . $icon . ' font-18"></i>
            </a>
            <a href="#" data-toggle-theme="" class="header-icon header-icon-4"><i class="fas fa-lightbulb font-18"></i></a>
            <a href="search_homepage.php" class="header-icon header-icon-3"><i class="fas fa-search"></i></a>

        </div>';
    } else {
        $html .= '<div class="header header-fixed header-logo-center">
        <a href="index.php" class="header-title">' . $header_title . '</a>
        <a href="' . $link_back . '" class="header-icon header-icon-1"><i class="fas ' . $icon . '"></i></a>
        <a href="#" data-toggle-theme class="header-icon header-icon-4"><i class="fas fa-lightbulb"></i></a>
        <a href="search_homepage.php" class="header-icon header-icon-3"><i class="fas fa-search"></i></a>
    </div>';
    }
    
    if ($footer_menu == 1) {
        $html .= '<div id="footer-bar" class="footer-bar-4 ">
                <a href="#" class="tab-link active-nav" data-tab="tab-1">
                <img src="   https://cdn-icons-png.flaticon.com/512/4481/4481380.png " width="30" height="30" alt="" title="" class="img-small">

                    <span>Beranda</span>
                </a>
                <a href="#" class="tab-link" data-tab="tab-2">
                <img src="   https://cdn-icons-png.flaticon.com/512/4481/4481070.png " width="30" height="30" alt="" title="" class="img-small">
                    <span>Info</span>
                </a>
                <a href="#" class="tab-link" data-tab="tab-3">
                <img src="   https://cdn-icons-png.flaticon.com/512/4481/4481387.png " width="30" height="30" alt="" title="" class="img-small">
                    <span>Agenda</span>
                </a>
                <a href="#" class="tab-link" data-tab="tab-4">
                <img src="   https://cdn-icons-png.flaticon.com/512/4481/4481135.png " width="30" height="30" alt="" title="" class="img-small">
                    <span>sdssa</span>
                </a>
                <a href="#" class="tab-link" data-tab="tab-5">
                <img src="   https://cdn-icons-png.flaticon.com/512/4481/4481330.png " width="30" height="30" alt="" title="" class="img-small">
                    <span>Settings</span>
                </a>
            </div>';
    }

    $html .= '<div class="page-content ' . $header_style . '">';
    return $html;
}
function checkDefaultPassword($pass, $hashed_password) {
    if (password_verify($pass, $hashed_password)) {
        echo '<a href="update-password.php" ><div class=" alert alert-small rounded-s shadow-xl bg-red-dark" role="alert">
    <span><i class="fa fa-times"></i></span>
    <strong>Harap ubah password Anda!</strong>
    <button type="button" class="close color-white opacity-60 font-16" data-bs-dismiss="alert" aria-label="Close">×</button>
</div></a>
';
        // Kata sandi cocok, izinkan akses
    } else {
        echo "";
        // Kata sandi tidak cocok, tolak akses
    }
}

function uploadGambar($file, $uploadPath) {
    $targetDir = $uploadPath;
    $targetFile = $targetDir . basename($file["name"]);
    $uploadOk = 1;
    $imageFileType = strtolower(pathinfo($targetFile, PATHINFO_EXTENSION));

    // Cek apakah file adalah gambar atau bukan
    $check = getimagesize($file["tmp_name"]);
    if($check !== false) {
        echo "File adalah gambar - " . $check["mime"] . ".";
        $uploadOk = 1;
    } else {
        echo "File bukan gambar.";
        $uploadOk = 0;
    }

    // Cek apakah file sudah ada
    if (file_exists($targetFile)) {
        echo "Maaf, file sudah ada.";
        $uploadOk = 0;
    }

    // Batasi jenis file yang diizinkan (contoh: hanya menerima gambar JPEG)
    if($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg"
    && $imageFileType != "gif") {
        echo "Maaf, hanya file JPG, JPEG, PNG, dan GIF yang diperbolehkan.";
        $uploadOk = 0;
    }

    // Cek jika $uploadOk bernilai 0, maka upload ditolak
    if ($uploadOk == 0) {
        echo "Maaf, file tidak diunggah.";
    } else {
        // Jika semuanya baik, coba untuk mengunggah file
        if (move_uploaded_file($file["tmp_name"], $targetFile)) {
            echo "File ". basename($file["name"]). " telah berhasil diunggah.";
        } else {
            echo "Maaf, ada kesalahan saat mengunggah file.";
        }
    }
}

function waktuUpload($timestamp) {
    $now = time();
    $diff = $now - $timestamp;

    if ($diff < 60) {
        return $diff . " detik yang lalu";
    } elseif ($diff < 3600) {
        $minutes = floor($diff / 60);
        return $minutes . " menit yang lalu";
    } elseif ($diff < 86400) {
        $hours = floor($diff / 3600);
        return $hours . " jam yang lalu";
    } else {
        $days = floor($diff / 86400);
        return $days . " hari yang lalu";
    }
}

// Contoh penggunaan
// $timestamp = strtotime("2023-10-20 12:00:00"); // Gantilah ini dengan timestamp unggahan Anda
// echo waktuUpload($timestamp);


function generateRandomToken($length = 32) {
    // Karakter yang diizinkan dalam token
    $characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    // Inisialisasi token kosong
    $token = '';

    // Generate token secara acak dengan panjang yang ditentukan
    for ($i = 0; $i < $length; $i++) {
        $token .= $characters[random_int(0, strlen($characters) - 1)];
    }

    return $token;
}

// Contoh penggunaan
// $randomToken = generateRandomToken();
// echo $randomToken;

function encrypt($data, $key) {
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    return base64_encode($iv . $encrypted);
}

function decrypt($data, $key) {
    $data = base64_decode($data);
    $ivSize = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($data, 0, $ivSize);
    $encrypted = substr($data, $ivSize);
    return openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);
}

// Contoh penggunaan
// $key = 'YourSecretKey'; // Gantilah dengan kunci rahasia Anda.
// $text = 'Hello, World!';
// $encrypted = encrypt($text, $key);
// echo "Encrypted: " . $encrypted . "<br>";
// $decrypted = decrypt($encrypted, $key);
// echo "Decrypted: " . $decrypted;


function calculateAge($birthDate) {
    $today = new DateTime();
    $birthdate = new DateTime($birthDate);
    $age = $today->diff($birthdate);
    return $age->y;
}

// Example usage:
// $birthday = "1990-05-15";
// $age = calculateAge($birthday);
// echo "You are " . $age . " years old.";

function greetBasedOnTime() {
    $currentHour = date('G');
    $greeting = "";

    if ($currentHour >= 5 && $currentHour < 12) {
        $greeting = "Selamat Pagi";
    } elseif ($currentHour >= 12 && $currentHour < 17) {
        $greeting = "Selamat Siang";
    } elseif ($currentHour >= 17 && $currentHour < 20) {
        $greeting = "Selamat Sore";
    } else {
        $greeting = "Selamat Malam";
    }

    return $greeting;
}

// Example usage:
// $greet = greetBasedOnTime();
// echo $greet;


function calculateDueDate($startDate, $daysToAdd) {
    $dueDate = date('Y-m-d', strtotime($startDate . ' + ' . $daysToAdd . ' days'));
    return $dueDate;
}

// Example usage:
// $startDate = '2023-10-23';  // Today's date
// $daysToAdd = 7;  // Adding 7 days for the due date
// $dueDate = calculateDueDate($startDate, $daysToAdd);
// echo "Jatuh tempo: " . $dueDate;

//////////////////
function tampilkanFAQ($database) {
    $berita = $database->read('faq', '', '15');
    
    if ($berita) {
        foreach ($berita as $news) {
            echo '<div class="divider mt-3 mb-3"></div>
            <h5 href="#FAQ' . $news['id'] . '" data-bs-toggle="collapse" role="button" class="font-600 collapsed" aria-expanded="false">
            ' . $news['question'] . '
                <i class="fa fa-angle-down float-end me-2 mt-1 opacity-50 font-10"></i>
            </h5>
            <div class="collapse" id="FAQ' . $news['id'] . '" style="">
                <p class="pb-3">
                ' . $news['answer'] . '
                // ' . potongTeks($news['answer']) . '
                </p>
            </div>';
        }
    } else {
        echo 'Tidak ada data berita.';
    }
}

// Cara panggil function ini:
// Menampilkan data mahasiswa
function tampilkanBeritaCard($database) {
    $berita = $database->read('berita', '', 3);
    // if ($template == 1) {
        if ($berita) {
            foreach ($berita as $news) {
                echo '<a href="berita-detail.php?id=' . $news['id'] . '"><div class="card card-style" style="background-image: url(img/news/' . $news['gambar'] . ');" data-card-height="260">
                    <div class="card-top no-click p-2 m-1">
                        <h1 class="color-white font-19 mb-0">1500 kcal</h1>
                        <p class="color-white mb-0 mt-n2 font-9 line-height-xs">
                            1 Hour, 20 Minutes
                        </p>
                    </div>
                    <div class="card-top p-3">

                    </div>
                    <div class="card-bottom m-2">
                        <div class="d-block px-2 py-2 rounded-m">
                            <div class="pe-3">
                                <h1 class="color-white font-5 font-800 mb-0">' . $news['judul'] . '</h1>
                                <p class="color-white font-12 mb-0 line-height-s opacity-70">' . potongTeks($news['isi']) . '</p>
                            </div>
                        </div>
                    </div>
                    <div class="card-overlay bg-gradient opacity-80"></div>
                </div></a>';
            }
        } else {
            echo 'Tidak ada data berita.';
        }
    // } 
    
}