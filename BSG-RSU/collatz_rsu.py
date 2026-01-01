"""
Collatz-VN-XOR Cipher Implementation
Project: Collatz Conjecture Based Crypto & Compression
Author: [Senin Adın/Github Kullanıcı Adın]

Description:
Bu modül, Collatz Sanısı (3n+1) üzerine kurulu bir sözde-rastgele sayı üreteci (PRNG) içerir.
İstatistiki denge için 'Von Neumann Whitening' ve güvenlik için 'Dynamic XOR' tekniklerini kullanır.
"""

import sys

class CollatzCrypto:
    def __init__(self, seed):
        """
        Başlangıç tohumu (seed) ile şifreleme motorunu başlatır.
        """
        self.initial_seed = seed
        self.n = seed
        self.last_output_bit = 0  # Feedback mekanizması için
        self.steps_taken = 0

    def _get_next_collatz_bit(self):
        """
        Collatz dizisinden (3n+1) bir sonraki ham biti üretir.
        Döngüye girerse (4-2-1) otomatik olarak yeniden tohumlama yapar.
        """
        if self.n <= 1:
            # Re-seed mekanizması: Basit ama etkili bir sıçrama
            self.n = self.initial_seed + self.steps_taken + 0xBADC0DE

        if self.n % 2 == 0:
            self.n = self.n // 2
        else:
            self.n = 3 * self.n + 1

        self.steps_taken += 1
        return self.n % 2

    def generate_keystream(self, length):
        """
        İstenilen uzunlukta (length) bit dizisi üretir.
        Yöntem: Collatz Ham Veri -> Von Neumann Düzeltmesi -> Dinamik XOR
        """
        keystream = []
        while len(keystream) < length:
            # 1. Adım: Von Neumann için iki bit çek
            b1 = self._get_next_collatz_bit()
            b2 = self._get_next_collatz_bit()

            candidate = None

            # 2. Adım: Von Neumann Kuralı (Bias Temizleme)
            # 00 ve 11 -> Atılır
            # 01 -> 0
            # 10 -> 1
            if b1 == 0 and b2 == 1:
                candidate = 0
            elif b1 == 1 and b2 == 0:
                candidate = 1

            # 3. Adım: Dinamik XOR (Karıştırma / Obfuscation)
            if candidate is not None:
                final_bit = candidate ^ self.last_output_bit
                keystream.append(final_bit)
                self.last_output_bit = final_bit  # State güncelleme

        return keystream

# --- Yardımcı Fonksiyonlar ---

def text_to_bits(text):
    """Metni bit listesine çevirir (UTF-8)."""
    bits = []
    for char in text:
        bin_val = bin(ord(char))[2:].zfill(8)
        bits.extend([int(b) for b in bin_val])
    return bits

def bits_to_text(bits):
    """Bit listesini metne çevirir."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8: break
        char_val = int("".join(str(b) for b in byte), 2)
        try:
            chars.append(chr(char_val))
        except ValueError:
            chars.append('?') # Hatalı karakter
    return "".join(chars)

def process_message(message_data, seed, mode='encrypt'):
    """Mesajı şifreler veya çözer (Simetrik XOR işlemi)."""

    if mode == 'encrypt':
        # Girdi string ise bitlere çevir
        if isinstance(message_data, str):
            data_bits = text_to_bits(message_data)
        else:
            data_bits = message_data
    else:
        # Decrypt modunda girdinin zaten bit listesi olduğunu varsayıyoruz
        data_bits = message_data

    # Anahtar akışı (Keystream) üret
    engine = CollatzCrypto(seed)
    keystream = engine.generate_keystream(len(data_bits))

    # XOR İşlemi (Şifreleme ve Çözme aynıdır)
    processed_bits = [(d ^ k) for d, k in zip(data_bits, keystream)]

    return processed_bits

# --- Ana Çalıştırma Bloğu (Demo) ---
if __name__ == "__main__":
    print(">>> COLLATZ-VN-XOR CRYPTO SYSTEM <<<")

    # 1. Ayarlar
    MY_SEED = 123456789
    MY_MESSAGE = "Merhaba Dunya! Collatz sifresi test ediliyor ve istatistikler inceleniyor."

    print(f"[*] Seed: {MY_SEED}")
    print(f"[*] Mesaj: {MY_MESSAGE}")

    # 2. Şifreleme
    encrypted_bits = process_message(MY_MESSAGE, MY_SEED, mode='encrypt')

    # --- İSTATİSTİK ANALİZİ (YENİ EKLENEN KISIM) ---
    total_bits = len(encrypted_bits)
    count_0 = encrypted_bits.count(0)
    count_1 = encrypted_bits.count(1)
    ratio_0 = (count_0 / total_bits) * 100
    ratio_1 = (count_1 / total_bits) * 100

    print("-" * 40)
    print(f"[*] Sifreli Bit Uzunlugu: {total_bits} bit")
    print(f"[*] Bit Dagilimi        : {count_0} adet '0' | {count_1} adet '1'")
    print(f"[*] Denge Orani         : %{ratio_0:.2f} (0) - %{ratio_1:.2f} (1)")
    print("-" * 40)

    # Hex formatında gösterim
    encrypted_bytes = bytearray()
    for i in range(0, len(encrypted_bits), 8):
        byte = encrypted_bits[i:i+8]
        if len(byte) == 8:
            val = int("".join(str(b) for b in byte), 2)
            encrypted_bytes.append(val)
    print(f"[*] Sifreli (Hex): {encrypted_bytes.hex()}")

    # 3. Çözme
    decrypted_bits = process_message(encrypted_bits, MY_SEED, mode='decrypt')
    decrypted_text = bits_to_text(decrypted_bits)
    print(f"[*] Cozulen Mesaj: {decrypted_text}")

    # 4. Hatalı Anahtar Testi
    print("-" * 40)
    print("[!] Saldiri Testi (Yanlis Anahtar Denemesi):")
    wrong_bits = process_message(encrypted_bits, MY_SEED + 1, mode='decrypt')
    wrong_text = bits_to_text(wrong_bits)
    # Ekrana basilamayacak karakterleri temizleyip gosterelim
    clean_wrong_text = ''.join([c if c.isprintable() else '.' for c in wrong_text])
    print(f"[*] Sonuc: {clean_wrong_text}")