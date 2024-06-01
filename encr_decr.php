<?php

function generate_key($length = 16) {
    $bytes = openssl_random_pseudo_bytes($length);
    $tes = 'FY91' . $bytes;
    return bin2hex($tes);
}

function encrypt_string($plaintext, $key) {
    $cipher = "AES-128-CBC";
    $ivlen = openssl_cipher_iv_length($cipher);
    $iv = openssl_random_pseudo_bytes($ivlen);
    $ciphertext_raw = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv);
    $hmac = hash_hmac('sha256', $ciphertext_raw, $key, true);
    return base64_encode($iv.$hmac.$ciphertext_raw);
}

function decrypt_string($ciphertext, $key) {
    $cipher = "AES-128-CBC";
    $c = base64_decode($ciphertext);
    $ivlen = openssl_cipher_iv_length($cipher);
    $iv = substr($c, 0, $ivlen);
    $hmac = substr($c, $ivlen, 32);
    $ciphertext_raw = substr($c, $ivlen + 32);
    $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, OPENSSL_RAW_DATA, $iv);
    $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, true);
    if (hash_equals($hmac, $calcmac)) {
        return $original_plaintext;
    } else {
        return false; // Decryption failed
    }
}

// Example usage
$key = generate_key(); // Store this key safely for encryption and decryption
echo "Generated Key: <br>" . $key . "\n";
echo '<br>';
$plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`~!@#$%^&*()-_=+[{]}\\|;:'<.>/?\n;,";
$ciphertext = encrypt_string($plaintext, $key);
echo "Encrypted String: " . $ciphertext . "\n";
echo '<br>';
$decrypted_text = decrypt_string($ciphertext, $key);
echo '<br>';
if ($decrypted_text !== false) {
    echo "Original String: " . $decrypted_text . "\n";
} else {
    echo "Decryption failed!\n";
}
?>
