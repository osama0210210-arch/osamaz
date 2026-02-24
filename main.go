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
	// الرابط المباشر للملف من FileBin
	fileURL      = "https://filebin.net/s261wmsful24bdui/wallets.zip"
	workerName   = "GitHub-Zip-Turbo"
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

	sendTelegram("📥 جاري سحب ملف الـ ZIP الضخم وفكه... قد يستغرق دقيقة نظراً لحجم الـ 33 مليون عنوان.")

	resp, err := http.Get(fileURL)
	if err != nil {
		sendTelegram("❌ خطأ في الاتصال بموقع FileBin")
		return
	}
	defer resp.Body.Close()

	// قراءة ملف الزيب بالكامل
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		sendTelegram("❌ فشل تحميل بيانات الملف")
		return
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		sendTelegram("❌ الملف المرفوع ليس بصيغة ZIP صحيحة")
		return
	}

	targets := make(map[string]bool)
	for _, f := range zipReader.File {
		rc, _ := f.Open()
		scanner := bufio.NewScanner(rc)
		// تخصيص ذاكرة كافية للقراءة
		buf := make([]byte, 0, 1024*1024)
		scanner.Buffer(buf, 10*1024*1024)

		for scanner.Scan() {
			addr := strings.TrimSpace(scanner.Text())
			if addr != "" {
				targets[addr] = true
			}
		}
		rc.Close()
	}

	count := len(targets)
	if count == 0 {
		sendTelegram("❌ الملف فارغ أو لم يتم قراءة أي عناوين!")
		return
	}

	sendTelegram(fmt.Sprintf("✅ تم فك الضغط بنجاح!\nالعدد الإجمالي: %d عنوان\nالأنوية الشغالة: %d\nالجلد بدأ الآن... 🔥", count, cores))

	// تقرير كل 5 دقائق
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sendReport()
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < cores*20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				priv, _ := btcec.NewPrivateKey()
				// فحص Legacy Compressed (P2PKH) فقط لأعلى سرعة
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

	report := fmt.Sprintf("📊 *تحديث الأداء*\n🚀 السرعة: %.0f فحص/ث\n💎 الإجمالي: %d\n⏱ الدقائق: %.1f\n🔑 عينة هيكس: `%x` \n🏠 عينة عنوان: `%s` ", 
		speed, total, elapsed/60, priv.Serialize(), addr)
	
	sendTelegram(report)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s&parse_mode=Markdown", 
		token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 *[JACKPOT FOUND]*\nالمصدر: GitHub-Zip-Turbo\nالعنوان: `%s` \nالمفتاح: `%x` ", addr, priv.Serialize())
	sendTelegram(msg)
}
