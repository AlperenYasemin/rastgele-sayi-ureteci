"""
Collatz-Based Image Compression & Quantization Test
Project: Collatz Conjecture Based Crypto & Compression
Author: [Senin Adın]

Description:
Bu modül, 'collatz_rsu' modülündeki PRNG yapısını kullanarak
standart JPEG sıkıştırma algoritması için dinamik ve kaotik
quantalama (quantization) tabloları üretir.
"""

import numpy as np
from scipy.fftpack import dct, idct
import sys

# DİKKAT: İlk dosyanın adı 'collatz_rsu.py' olmalıdır!
try:
    from collatz_rsu import CollatzCrypto
except ImportError:
    print("HATA: 'collatz_rsu.py' bulunamadı. Lütfen dosya adını kontrol et (tire yerine alt tire kullan).")
    sys.exit(1)


class CollatzQuantizer:
    def __init__(self, seed):
        self.seed = seed
        self.crypto = CollatzCrypto(seed)  # Motoru başlat

    def generate_byte(self):
        """Collatz akışından 8 bit çekip 1 tamsayı (0-255) oluşturur."""
        bits = self.crypto.generate_keystream(8)
        byte_val = int("".join(str(b) for b in bits), 2)
        return max(1, byte_val)  # Sıfıra bölünme hatasını önle

    def create_quant_table(self):
        """
        Kaotik Quantalama Tablosu Oluşturur.
        İyileştirme: İnsan gözü hassasiyetine göre (Psychovisual) ağırlıklandırılmıştır.
        """
        table = np.zeros((8, 8), dtype=int)

        for i in range(8):
            for j in range(8):
                # Collatz'dan ham veri al
                raw_val = self.generate_byte()

                # --- İYİLEŞTİRME MANTIĞI ---
                # Sol üst köşe (Düşük Frekans) -> Göz çok hassas -> Düşük değerler ver
                # Sağ alt köşe (Yüksek Frekans) -> Göz az hassas -> Yüksek değerler serbest

                distance = i + j  # Merkeze uzaklık (0-14 arası)

                if distance == 0:
                    # DC Katsayısı (En önemli piksel)
                    scaled_val = (raw_val % 16) + 1
                elif distance < 5:
                    # Düşük Frekanslar (Detaylar)
                    scaled_val = (raw_val % 30) + 5
                elif distance < 10:
                    # Orta Frekanslar
                    scaled_val = (raw_val % 100) + 10
                else:
                    # Yüksek Frekanslar (Gürültü) - Kaos serbest
                    scaled_val = max(10, raw_val)

                table[i][j] = scaled_val

        return table

    def dct_2d(self, block):
        """2 Boyutlu Ayrık Kosinüs Dönüşümü"""
        return dct(dct(block.T, norm='ortho').T, norm='ortho')

    def idct_2d(self, block):
        """Ters 2 Boyutlu DCT"""
        return idct(idct(block.T, norm='ortho').T, norm='ortho')

    def test_performance(self):
        """Standart JPEG ile Collatz Tablosunu karşılaştırır."""

        # 1. Test Verisi: Rastgele gri tonlamalı 8x8 blok
        # Değerleri -128 ile ortalıyoruz (JPEG standardı)
        np.random.seed(42)  # Her çalıştırmada aynı rastgele blok gelsin diye sabitliyoruz
        original_block = np.random.randint(0, 256, (8, 8)) - 128

        # 2. Standart JPEG Luminance Tablosu (Referans)
        std_quant_table = np.array([
            [16, 11, 10, 16, 24, 40, 51, 61],
            [12, 12, 14, 19, 26, 58, 60, 55],
            [14, 13, 16, 24, 40, 57, 69, 56],
            [14, 17, 22, 29, 51, 87, 80, 62],
            [18, 22, 37, 56, 68, 109, 103, 77],
            [24, 35, 55, 64, 81, 104, 113, 92],
            [49, 64, 78, 87, 103, 121, 120, 101],
            [72, 92, 95, 98, 112, 100, 103, 99]
        ])

        # 3. Collatz Tablosu
        collatz_table = self.create_quant_table()

        print(f"\n--- SIKIŞTIRMA PERFORMANS TESTİ (Seed: {self.seed}) ---")
        self._evaluate(original_block, std_quant_table, "Standart JPEG")
        print("-" * 50)
        self._evaluate(original_block, collatz_table, "Collatz Crypto-Compression")

    def _evaluate(self, block, q_table, name):
        # A. İleri Dönüşüm (DCT)
        dct_block = self.dct_2d(block)

        # B. Quantalama (Veri Kaybı Burada Olur)
        with np.errstate(divide='ignore'):
            quantized = np.round(dct_block / q_table)

        # C. İstatistikler
        zeros = np.sum(quantized == 0)
        compression_ratio = (zeros / 64) * 100

        # D. Geri Dönüşüm (Reconstruction)
        rec_dct = quantized * q_table
        rec_block = self.idct_2d(rec_dct)

        # E. Hata Hesabı (MSE)
        mse = np.mean((block - rec_block) ** 2)

        print(f"[{name}]")
        print(f"  Sıfır Oranı (Sıkıştırma): %{compression_ratio:.2f}")
        print(f"  Hata Oranı (MSE)        : {mse:.2f}")
        print(f"  Tablo Örneği (İlk Satır): {q_table[0]}")


if __name__ == "__main__":
    # Testi çalıştır
    tester = CollatzQuantizer(seed=1923)
    tester.test_performance()