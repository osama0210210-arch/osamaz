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
	"sync"
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

	sendTelegram("🚀 *تحديث النظام: الفحص الجديد*\nجاري شحن الـ 21 مليون عنوان...")

	client := &http.Client{Timeout: 40 * time.Minute}
	resp, err := client.Get(fileURL)
	if err != nil {
		sendTelegram("❌ خطأ في الاتصال")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	zipReader, _ := zip.NewReader(bytes.NewReader(body), int64(len(body)))

	targets := make(map[string]struct{}, 22000000)
	for _, f := range zipReader.File {
		rc, _ := f.Open()
		scanner := bufio.NewScanner(rc)
		buf := make([]byte, 0, 1024*1024)
		scanner.Buffer(buf, 10*1024*1024)
		for scanner.Scan() {
			addr := strings.TrimSpace(scanner.Text())
			if len(addr) > 25 {
				targets[addr] = struct{}{}
			}
		}
		rc.Close()
	}

	sendTelegram(fmt.Sprintf("✅ تم تفعيل %d هدف!\n🔥 الفحص الجديد (C/U) يعمل الآن...", len(targets)))

	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sendReport()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < cores*25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				priv, _ := btcec.NewPrivateKey()
				
				// 1. النوع الأول: Compressed (الأكثر شيوعاً)
				addrC := encodeAddress(priv.PubKey().SerializeCompressed())
				if _, found := targets[addrC]; found {
					sendFound(addrC, "Compressed", priv)
				}

				// 2. النوع الثاني: Uncompressed (المحافظ القديمة جداً)
				addrU := encodeAddress(priv.PubKey().SerializeUncompressed())
				if _, found := targets[addrU]; found {
					sendFound(addrU, "Uncompressed", priv)
				}

				atomic.AddUint64(&totalChecked, 1)
			}
		}()
	}
	wg.Wait()
}

func sendReport() {
	elapsed := time.Since(startTime).Seconds()
	total := atomic.LoadUint64(&totalChecked)
	speed := float64(total) / elapsed

	// توليد عينة حية للتقرير
	priv, _ := btcec.NewPrivateKey()
	hexKey := fmt.Sprintf("%x", priv.Serialize())
	addrC := encodeAddress(priv.PubKey().SerializeCompressed())
	addrU := encodeAddress(priv.PubKey().SerializeUncompressed())

	report := fmt.Sprintf("📊 *تقرير سيرفر جديد*\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🚀 السرعة: %.0f مفتاح/ث\n"+
		"💎 الإجمالي: %d\n"+
		"⏱ المدة: %.1f دقيقة\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🔑 عينة هيكس:\n`%s` \n"+
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
	msg := fmt.Sprintf("💰 *[JACKPOT FOUND]*\n\nنوع المحفظة: %s\nالعنوان: `%s` \nالمفتاح: `%x` ", kind, addr, priv.Serialize())
	sendTelegram(msg)
}
