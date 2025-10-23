

function goToChat() {
    window.location.href = "chat.html";
}

// Ayarlar menüsünü göster/gizle
document.addEventListener("DOMContentLoaded", function () {
    const settingsIcon = document.getElementById("settings-icon");
    const settingsMenu = document.getElementById("settings-menu");

    if (settingsIcon && settingsMenu) {
        settingsIcon.addEventListener("click", function () {
            settingsMenu.classList.toggle("visible");
        });
    }
});

function clearChat() {
    const button = event.target;
    button.innerText = "⏳ Temizleniyor...";
    button.disabled = true;

    fetch("/clear_chat", { method: "POST" })
        .then(r => r.json())
        .then(data => {
            document.getElementById("chatOut").innerText = data.mesaj || "✅ Temizlik tamamlandı.";
        })
        .catch(err => {
            document.getElementById("chatOut").innerText = "⚠️ Hata oluştu.";
        })
        .finally(() => {
            button.innerText = "🧹 Şimdi Temizle";
            button.disabled = false;
        });
}

function openExportAllModal() {
    document.getElementById("exportAllModal").style.display = "flex";
}

function closeExportAllModal() {
    document.getElementById("exportAllModal").style.display = "none";
}

function validateExportAllForm() {
    const pass = document.getElementById("fullZipPass").value.trim();
    if (!pass) {
        alert("Lütfen bir şifre girin.");
        return false;
    }
    return true;
}

function openSearchModal() {
    document.getElementById("searchModal").style.display = "flex";
}

function closeSearchModal() {
    document.getElementById("searchModal").style.display = "none";
}

function runSearch() {
    const query = document.getElementById("searchQuery").value.trim();
    const output = document.getElementById("searchOut");

    if (!query) {
        output.innerHTML = "<p>Lütfen bir arama kelimesi girin.</p>";
        return;
    }

    fetch("/search-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: query })
    })
    .then(res => res.json())
    .then(data => {
        if (!data.success) {
            output.innerHTML = `<p style="color:red">${data.message}</p>`;
            return;
        }

        if (data.matches.length === 0) {
            output.innerHTML = "<p>Sonuç bulunamadı.</p>";
            return;
        }

        output.innerHTML = `<p><b>${data.matches.length}</b> sonuç bulundu:</p><ul>` +
            data.matches.map(m => `<li><b>${m.role}</b>: ${m.content}</li>`).join("") +
            "</ul>";
    })
    .catch(err => {
        output.innerHTML = "<p style='color:red'>Bir hata oluştu.</p>";
    });
}

