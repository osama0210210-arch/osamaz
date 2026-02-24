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
	// رابط Hugging Face المباشر الخاص بك
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

	sendTelegram("🚀 *بدء الهجوم الشامل*\nجاري سحب الملايين من Hugging Face...")

	// مهلة تحميل كافية لسحب الـ 400+ ميجا
	client := &http.Client{Timeout: 40 * time.Minute}
	resp, err := client.Get(fileURL)
	if err != nil {
		sendTelegram("❌ فشل الاتصال برابط Hugging Face")
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		sendTelegram("❌ انقطع التحميل أثناء قراءة البيانات")
		return
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		sendTelegram("❌ الملف ليس ZIP صحيح. تأكد من اكتمال الرفع على Hugging Face.")
		return
	}

	// استخدام struct{} لتقليل استهلاك الرام إلى الصفر تقريباً لكل عنوان
	targets := make(map[string]struct{}, 25000000)
	for _, f := range zipReader.File {
		rc, _ := f.Open()
		scanner := bufio.NewScanner(rc)
		buf := make([]byte, 0, 1024*1024)
		scanner.Buffer(buf, 20*1024*1024)

		for scanner.Scan() {
			addr := strings.TrimSpace(scanner.Text())
			if len(addr) > 25 {
				targets[addr] = struct{}{}
			}
		}
		rc.Close()
	}

	count := len(targets)
	sendTelegram(fmt.Sprintf("✅ *تم الشحن بنجاح!*\nالعدد: %d عنوان\nالحالة: الصيد بدأ الآن... 🔥", count))

	go func() {
		for {
			time.Sleep(5 * time.Minute)
			sendReport()
		}
	}()

	var wg sync.WaitGroup
	// تشغيل مكثف لزيادة سرعة الفحص
	for i := 0; i < cores*30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				priv, _ := btcec.NewPrivateKey()
				// فحص عناوين Legacy (التي تبدأ برقم 1)
				addr := encodeAddress(priv.PubKey().SerializeCompressed())
				if _, found := targets[addr]; found {
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
	msg := fmt.Sprintf("📊 *تقرير الأداء*\n🚀 السرعة: %.0f/ث\n💎 الإجمالي: %d\n⏱ المدة: %.1f دقيقة", 
		speed, total, elapsed/60)
	sendTelegram(msg)
}

func sendTelegram(text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s&parse_mode=Markdown", 
		token, chatID, url.QueryEscape(text))
	http.Get(apiURL)
}

func sendFound(addr string, priv *btcec.PrivateKey) {
	msg := fmt.Sprintf("💰 *[JACKPOT FOUND]*\nAddr: `%s` \nKey: `%x` ", addr, priv.Serialize())
	sendTelegram(msg)
}
