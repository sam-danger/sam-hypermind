const input = document.getElementById("input");
const chat = document.getElementById("chat");
const girisMesaji = document.getElementById("giris-mesaji");

function sendMessage() {
    const mesaj = input.value.trim();
    if (!mesaj) return;

    appendMessage("user", mesaj);
kontrolEtVeAra(mesaj);  // 🔁 Hava durumu gibi komutlar otomatik kontrol edilir
input.value = "";

    appendTypingIndicator();

    fetch("/send_message", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_input: mesaj })
    })
    .then(response => response.json())
    .then(data => {
        removeTypingIndicator();
        const cevap = data.yanit || data.hata;

        // 🔄 Eski fonksiyon yerine bu kullanılacak
        appendMessageWithTools("sam", cevap);  
        speakSAM(cevap);  // Sesli okuma (isteğe bağlı)
    })
    .catch(err => {
        removeTypingIndicator();
        appendMessage("sam", "❌ HATA: " + err.message);
    });

    chat.scrollTop = chat.scrollHeight;
}


function kontrolEtVeAra(mesaj) {
  const temiz = mesaj.toLowerCase().trim();

  if (temiz.includes("hava durumu") || temiz.includes("hava nasıl") || temiz.includes("sıcaklık")) {
    const sehir = temiz
      .replace("hava durumu", "")
      .replace("hava nasıl", "")
      .replace("sıcaklık", "")
      .replace("nasıl", "")
      .replace("nedir", "")
      .replace("?", "")
      .trim();

    // Şehir adı belirtilmişse orayı gönder, yoksa genel sorgu
    if (sehir.length > 0) {
      internettenAra(sehir);
    } else {
      internettenAra("istanbul");
    }
  }
}



function appendMessage(role, text) {
    const messageDiv = document.createElement("div");
    messageDiv.className = role === "sam" ? "sam-message" : "user-message";
    messageDiv.textContent = `${role === "sam" ? "SAM: 🤖" : "🧍‍♂️ Sen:"} ${text}`;
    document.getElementById("chat").appendChild(messageDiv);
}


function appendTypingIndicator() {
    const typing = document.createElement("div");
    typing.id = "typing";
    typing.classList.add("message", "sam");
    typing.innerHTML = `<span class="typing">SAM yazıyor...</span>`;
    chat.appendChild(typing);
    chat.scrollTop = chat.scrollHeight;
}

function removeTypingIndicator() {
    const typing = document.getElementById("typing");
    if (typing) typing.remove();
}

function appendMessageWithTools(rol, text) {
    if (!text || text === "undefined") return;

    rol = rol.toLowerCase();
    if (rol === "sam" || rol === "assistant") rol = "sam";
    else rol = "user";

    const msg = document.createElement("div");
    msg.classList.add("message", rol);

    const prefix = rol === "user" ? "🧍‍♂️ Sen: " : "SAM: ";
    const span = document.createElement("span");
    span.classList.add("typing");
    msg.appendChild(span);

    let plainTextForAudio = text;

    if (rol === "sam") {
        const enriched = enrichSAMMessage(text);
        text = enriched.html;
        plainTextForAudio = enriched.plain;

        const tools = document.createElement("div");
        tools.className = "sam-tools";
        tools.innerHTML = `
            <span class="emoji-reactions">
                <span class="emoji" onclick="setReaction(this, 'like')">👍</span>
                <span class="emoji" onclick="setReaction(this, 'dislike')">👎</span>
                <span class="emoji" onclick="setReaction(this, 'smile')">😄</span>
            </span>
            <i class="fa-solid fa-volume-high" onclick="okuCevap('${plainTextForAudio.replace(/'/g, "\\'")}')"></i>
            <i class="fa-solid fa-copy" onclick="kopyalaCevap('${text.replace(/'/g, "\\'")}', this.closest('.message'))" title="Kopyala"></i>
        `;
        msg.appendChild(tools);
    }

    chat.appendChild(msg);
    chat.scrollTop = chat.scrollHeight;

    let index = 0;
    const yaz = setInterval(() => {
        span.innerHTML = prefix + text.substring(0, index + 1);
        index++;
        if (index >= text.length) {
            clearInterval(yaz);
            span.classList.remove("typing");
        }
    }, 25);
}



function enrichSAMMessage(text) {
    const emojiMap = {
        "hedef|amaç|odak": "🎯",
        "tamam|doğru|onay": "✅",
        "fikir|öneri|yaratıcı": "💡",
        "uyarı|dikkat|tehlike": "⚠️",
        "veri|istatistik|grafik": "📊",
        "ara|incele|bul": "🔍",
        "kitap|öğren|okul|eğitim": "📚",
        "yapay zeka|sam|asistan|bot": "🤖",
        "ayar|düzenle|sistem": "🔧",
        "mesaj|sohbet|konuşma": "💬",
        "şifre|parola|gizlilik|güvenlik": "🔐",
        "kaydet|dosya|yedek": "💾",
        "test|deneme|analiz": "🧪",
        "temizle|sil|kaldır": "🧹",
        "klasör|arşiv|bölüm": "🗂️",
        "yenile|tekrar|döngü": "🔄",
        "indir|çek": "📥",
        "yükle|gönder": "📤",
        "zaman|saat|tarih|randevu|plan": "⏰",
        "sabitle|önem": "📌",
        "etiket|başlık": "🏷️",
        "yoğun|aktif|sıcak": "🔥",
        "soğuk|donma": "❄️",
        "internet|bağlantı|web": "🌐",
        "duyuru|bilgilendirme": "📣",
        "bilgisayar|arayüz|ekran": "💻",
        "mikrofon|ses": "🎤",
        "sessiz|kapalı": "🔇",
        "yüksek|sesli": "🔊",
        "rehber|yön|navigasyon": "🧭",
        "telefon|arama": "📞",
        "sinyal|çekim": "📶",
        "enerji|pil": "🔋",
        "acil|alarm": "🚨",
        "özellik|hediye": "🎁",
        "form|belge": "🧾",
        "konum|yön": "📍",
        "kontrol|panel": "🎛️",
        "video|oynat": "📽️",
        "tasarım|görsel|renk": "🎨",
        "uyku|gece": "🌙",
        "gündüz|ışık": "🌞",
        "kullanıcı|giriş": "🧍",
        "bilgi|açıklama": "ℹ️",
        "oyun|etkileşim": "🎮",
        "gizli|araştır": "🕵️‍♂️",
        "proje|iş": "💼",
        "gelişme|başlat": "🚀",
        "hata|kritik": "💣",
        "çöp|gereksiz": "🗑️",
        "mail|posta|e-posta": "✉️",
        "maliyet|ücret|para": "💰",
        "dünya|küresel": "🌍",
        "log|kayıt": "🧾",
        "görsel|resim": "🖼️",
        "kutlama|başarı": "🎉",
        "ödül|birinci": "🥇",
        "modül|eklenti|bileşen": "🧩",
        "bilgisayar|teknoloji": "💻",
        "kamera|çekim": "📸",
        "mikrofon|kayıt": "🎙️",
        "müzik|ses|melodi": "🎵",
        "görüşme|konuşma": "🗣️",
        "ajanda|not": "📔",
        "takvim|planlama": "🗓️",
        "yazılım|uygulama": "🖥️",
        "video|klip|görüntü": "🎞️",
        "ses|çıkış": "🔈",
        "giriş|input": "🔣",
        "şifre|gizli": "🛡️",
        "sistem|çekirdek": "🧬",
        "arayüz|görsel": "🖼️",
        "veritabanı|database": "🗄️",
        "bulut|cloud": "☁️",
        "çevrimiçi|online": "🌐",
        "ağ|network": "🕸️",
        "sunucu|server": "🖧",
        "hizmet|servis": "🔧",
        "kullanıcı|hesap": "👤",
        "profil|özgeçmiş": "📝",
        "destek|yardım": "🆘",
        "mesaj|gönderi": "💌",
        "bildirim|uyarı": "🔔",
        "geri bildirim|feedback": "🗨️",
        "kopyala|yapıştır": "📋",
        "renk|tema": "🎨",
        "şema|yapı": "🧱",
        "analiz|değerlendirme": "📈",
        "karşılaştırma|benchmark": "⚖️",
        "test|çalıştır": "🧪",
        "hata|bug": "🐞",
        "otomatik|auto": "♻️",
        "karanlık|gece modu": "🌚",
        "ışık|aydınlık": "🌞",
        "bağlantı|link": "🔗",
        "tarayıcı|browser": "🌐",
        "sürüm|versiyon": "📦",
        "güncelleme|update": "🔄",
        "lisans|izin": "📜",
        "döküman|belge": "📄",
        "görünüm|arayüz": "🧾",
        "çözüm|yöntem": "🛠️",
        "proje|iş": "🏗️",
        "not|hatırlatma": "📝",
        "istatistik|sayı": "📊",
        "işlem|faaliyet": "📌",
        "etiket|tag": "🏷️",
        "alarm|zamanlayıcı": "⏱️",
        "başarı|tamamlandı": "🏆",
        "kayıt|log": "🧾",
        "kutu|öğe": "📦",
        "dosya|belge": "🗂️",
        "temizlik|boşalt": "🧼",
        "robot|yapay zeka": "🤖",
        "engelle|blokla": "🚫",
        "ayarlar|ayar": "⚙️",
        "yeniden başlat|reset": "🔁",
        "geri yükle|backup": "♻️",
        "geri al|undo": "↩️",
        "ilerle|devam": "➡️",
        "başlat|çalıştır": "▶️",
        "durdur|bitir": "⏹️",
        "duraklat|pause": "⏸️",
        "sil|temizle": "🗑️",
        "sık sorulan|sss": "❓",
        "giriş|login": "🔐",
        "çıkış|logout": "🚪",
        "dondur|kilitle": "🧊",
        "arama|sorgu": "🔍",
        "filtre|ara": "🧃",
        "yeniden dene|tekrar": "🔁",
        "başlık|öz": "📌",
        "konu|içerik": "📚",
        "yorum|açıklama": "💬",
        "bekliyor|işleniyor": "⏳",
        "anlık|gerçek zamanlı": "🕒",
        "günlük|log": "📓",
        "sonuç|çıktı": "📤",
        "girdi|input": "📥",
        "eşleşme|karşılaştır": "🔁",
        "detay|incele": "🧵",
        "hızlı|acil": "🚀",
        "sakin|bekle": "🛑",
        "bildir|raporla": "📣",
        "hazır|uygun": "📦",
        "yükleniyor|işleniyor": "⏳",
        "aktif|çalışıyor": "🟢",
        "pasif|devre dışı": "🔴",
        "hizmet dışı|arıza": "⚠️",
        "denetim|kontrol": "🎛️",
        "hesap|üye": "👥",
        "yetki|rol": "🧑‍💼",
        "kilitli|erişim yok": "🔒",
        "erişilebilir|açık": "🔓",
        "tanımlı|bağlı": "📎",
        "tanımsız|kopuk": "❌",
        "seçili|aktif": "☑️",
        "boş|tanımsız": "⬜"
        // Listeye eklenebilir: sadece anahtarları büyütme
    };

   const lines = text.split("\n");
    const enrichedLines = [];
    const cleanLines = [];

    lines.forEach(line => {
        const lower = line.toLowerCase();
        let foundEmoji = "🤖";
        for (const pattern in emojiMap) {
            const regex = new RegExp(`\\b(${pattern})\\b`, "i");
            if (regex.test(lower)) {
                foundEmoji = emojiMap[pattern];
                break;
            }
        }
        enrichedLines.push(`${foundEmoji} ${line}`);
        cleanLines.push(line);  // emojisiz versiyonu
    });

    return {
        html: enrichedLines.join("<br>"),
        plain: cleanLines.join("\n")
    };
}






function setReaction(selectedEmoji, type) {
    const parent = selectedEmoji.parentElement;
    const emojis = parent.querySelectorAll(".emoji");

    // Eğer grup zaten kilitliyse işlem yapma
    if (parent.classList.contains("locked")) return;

    // Seçilen emojiye aktif sınıfı ekle
    selectedEmoji.classList.add("active-reaction");

    // Diğerlerine pasif (disabled) sınıfı ekle
    emojis.forEach(emoji => {
        if (emoji !== selectedEmoji) {
            emoji.classList.add("disabled");
        }
    });

     parent.classList.add("locked");

    // 👇 BURASI EKLENEN KISIM
    const mesajlar = {
        like: "Beğendiniz.",
        dislike: "Beğenmediniz.",
        smile: "Gülümsediniz."
    };
    showEmojiNotification(mesajlar[type]);
}




function okuCevap(metin, btn = null) {
    if (speechSynthesis.speaking && currentUtterance) {
        speechSynthesis.cancel();
        if (currentlySpeakingBtn) {
            currentlySpeakingBtn.innerHTML = `<i class="fas fa-volume-up"></i>`;
        }
        currentUtterance = null;
        currentlySpeakingBtn = null;
        return;
    }

    const utterance = new SpeechSynthesisUtterance(metin);
    utterance.lang = "tr-TR";
    speechSynthesis.speak(utterance);

    currentUtterance = utterance;
    currentlySpeakingBtn = btn;

    if (btn) {
        btn.innerHTML = `<i class="fas fa-stop"></i>`;
    }

    utterance.onend = () => {
        if (btn) btn.innerHTML = `<i class="fas fa-volume-up"></i>`;
        currentUtterance = null;
        currentlySpeakingBtn = null;
    };
}

function speakSAM(metin) {
    fetch("/speak", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: metin })
    })
    .then(res => res.blob())
    .then(blob => {
        const url = URL.createObjectURL(blob);
        const audio = new Audio(url);
        audio.play();
    })
    .catch(err => console.error("Sesli okuma hatası:", err));
}

function kopyalaCevap(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast("📋 Mesaj panoya kopyalandı.");
    });
}



function checkConnection() {
    const start = Date.now();
    fetch("/ping")
        .then(() => {
            const ms = Date.now() - start;
            document.getElementById("status-text").textContent = `Aktif ✅ | ${ms} ms`;
        })
        .catch(() => {
            document.getElementById("status-text").textContent = "Kesildi ❌";
        });
}

function startListening() {
    const recognition = new (window.SpeechRecognition || window.webkitSpeechRecognition)();
    recognition.lang = 'tr-TR';
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;

    const micButton = document.getElementById("mic-button");
    const micStatus = document.getElementById("mic-status");

    micButton.classList.add("listening");
    micStatus.style.display = "block";

    recognition.start();

    recognition.onresult = (event) => {
        input.value = event.results[0][0].transcript;
    };

    recognition.onerror = (event) => {
        alert("🎤 Mikrofon hatası: " + event.error);
    };

    recognition.onend = () => {
        micButton.classList.remove("listening");
        micStatus.style.display = "none";
    };
}

window.onload = () => {
    girisMesaji.innerHTML = "🧠 Derin öğrenme başlatıldı... Lütfen bekleyin..";
    setTimeout(() => {
        girisMesaji.innerHTML = "SAM: Merhaba. Size nasıl yardımcı olabilirim?";
    }, 3500);   


    // ✅ Geçmiş mesajları doğrudan yükle
    fetch("/get_chat_history")
        .then(response => response.json())
        .then(data => {
            data.forEach(msg => {
                appendMessageDirectWithTools(msg.role, msg.message); // 👈 Artık animasyon yok
            });
        });

    setTimeout(() => {
        chat.scrollTop = chat.scrollHeight;
    }, 100);
};



function appendMessageDirectWithTools(rol, text) {
    if (!text || text === "undefined") return;

    rol = rol.toLowerCase();
    if (rol === "sam" || rol === "assistant") rol = "sam";
    else rol = "user";

    const msg = document.createElement("div");
    msg.classList.add("message", rol);

    if (rol === "sam") {
        const enriched = enrichSAMMessage(text);

        const span = document.createElement("span");
        span.innerHTML = "SAM: " + enriched.html;
        msg.appendChild(span);

        const tools = document.createElement("div");
        tools.className = "sam-tools";
        tools.innerHTML = `
            <span class="emoji-reactions">
                <span class="emoji" onclick="setReaction(this, 'like')">👍</span>
                <span class="emoji" onclick="setReaction(this, 'dislike')">👎</span>
                <span class="emoji" onclick="setReaction(this, 'smile')">😄</span>
            </span>
            <i class="fa-solid fa-volume-high" onclick="okuCevap('${enriched.plain.replace(/'/g, "\\'")}')"></i>
            <i class="fa-solid fa-copy" onclick="kopyalaCevap('${text.replace(/'/g, "\\'")}', this.closest('.message'))" title="Kopyala"></i>
        `;
        msg.appendChild(tools);
    } else {
        const span = document.createElement("span");
        span.textContent = "🧍‍♂️ Sen: " + text;
        msg.appendChild(span);
    }

    chat.appendChild(msg);
    chat.scrollTop = chat.scrollHeight;
}



function showEmojiNotification(text) {
    const uyarı = document.createElement("div");
    uyarı.className = "emoji-bildirim";
    uyarı.textContent = text;
    document.body.appendChild(uyarı);

    setTimeout(() => {
        uyarı.classList.add("gizle");
        setTimeout(() => uyarı.remove(), 500);
    }, 1500);
}


function showInlineToast(msgDiv, text) {
    const toast = document.createElement("div");
    toast.className = "inline-toast";
    toast.textContent = text;

    msgDiv.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 2000);
}



function handleVoiceCommand(command) {
    command = command.toLowerCase();

    if (command.includes("notlar")) {
        document.getElementById("goto-notlar").click();
    } else if (command.includes("veri") || command.includes("data")) {
        document.getElementById("goto-veri").click();
    } else if (command.includes("profil")) {
        document.getElementById("goto-profil").click();
    } else if (command.includes("anasayfa") || command.includes("ana sayfa") || command.includes("home")) {
        document.getElementById("goto-home").click();
    } else if (command.includes("sohbet") || command.includes("chat")) {
        document.getElementById("goto-chat").click();
    } else {
        console.log("🔍 Bilinmeyen komut:", command);
    }
}



async function internettenAra(kelime) {
  const chatBox = document.getElementById("chat");
  const loadingDiv = document.createElement("div");
  loadingDiv.classList.add("message", "sam");
  loadingDiv.innerHTML = "🔍 İnternetten bilgi aranıyor...";
  chatBox.appendChild(loadingDiv);

  try {
    const res = await fetch("/internet-search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: kelime })
    });

    const veri = await res.json();

    const cevapDiv = document.createElement("div");
    cevapDiv.classList.add("message", "sam");
    cevapDiv.innerHTML = `<strong>SAM:</strong> ${veri.sonuc}`;
    chatBox.appendChild(cevapDiv);

    // 🔊 SAM sesli okusun
    if (typeof speak === "function") speak(veri.sonuc);

    chatBox.scrollTop = chatBox.scrollHeight;
  } catch (e) {
    loadingDiv.innerHTML = "❌ Arama sırasında hata oluştu.";
  }
}


function internettenAra(sorgu) {
  fetch("/search", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: sorgu })
  })
  .then(res => res.json())
  .then(data => {
    if (data.results) {
      let html = "<b>🌐 İnternetten Bulunan Sonuçlar:</b><ul>";
      data.results.forEach(r => {
        html += `<li><a href="${r.link}" target="_blank">${r.title}</a><br><small>${r.snippet}</small></li>`;
      });
      html += "</ul>";
      appendMessage("sam", html);
    } else {
      appendMessage("sam", "Hiçbir sonuç bulunamadı.");
    }
  });
}


setInterval(checkConnection, 5000);
checkConnection();
