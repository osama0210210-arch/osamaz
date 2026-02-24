package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
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
	// تم تعديل الرابط ليكون مباشر 100%
	fileURL      = "https://www.dropbox.com/scl/fi/kpagj5u15zjeo0q5kg31t/wallets.txt?rlkey=0yc47js2rv5hvb2plcf9nqcgp&st=2xrliohq&dl=1"
	workerName   = "GitHub-Legacy-Turbo"
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

	sendTelegram(fmt.Sprintf("🚀 *انطلاق الجيش من Dropbox*\nالمصدر: [%s]\nالأنوية: %d\nجاري سحب الأهداف...", workerName, cores))

	resp, err := http.Get(fileURL)
	if err != nil {
		sendTelegram("❌ فشل سحب الملف من Dropbox")
		return
	}
	defer resp.Body.Close()

	targets := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	// مخصص لقراءة الملفات العملاقة (2.5 جيجا) بدون تعليق
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 20*1024*1024)

	for scanner.Scan() {
		addr := strings.TrimSpace(scanner.Text())
		if addr != "" {
			targets[addr] = true
		}
	}

	totalTargets := len(targets)
	sendTelegram(fmt.Sprintf("📥 *تم تحميل الأهداف!*\nالعدد: %d عنوان\nالحالة: الجلد بدأ الآن... 🔥", totalTargets))

	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sendReport()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < cores*16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				priv, _ := btcec.NewPrivateKey()
				// فحص Legacy Compressed فقط لأعلى سرعة
				addr := encodeAddress(priv.PubKey().SerializeCompressed())

				if targets[addr] {
					sendFound(addr, priv)
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
	
	priv, _ := btcec.NewPrivateKey()
	addr := encodeAddress(priv.PubKey().SerializeCompressed())

	report := fmt.Sprintf("📊 *تقرير الأداء (Legacy)*\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🤖 المصدر: [%s]\n"+
		"🚀 السرعة: %.0f فحص/ث\n"+
		"💎 الإجمالي: %d\n"+
		"⏱ الدقائق: %.1f\n"+
		"━━━━━━━━━━━━━━━\n"+
		"🔑 عينة هيكس: `%x` \n"+
		"🏠 عينة عنوان: `%s` ", 
		workerName, speed, total, elapsed/60, priv.Serialize(), addr)
	
	sendTelegram(report)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s&parse_mode=Markdown", 
		token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 *[JACKPOT FOUND]*\n\nAddr: `%s` \nKey: `%x` ", addr, priv.Serialize())
	sendTelegram(msg)
}
