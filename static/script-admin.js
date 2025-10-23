function listele() {
  fetch("http://127.0.0.1:5000/memory/list")
    .then(res => res.json())
    .then(data => {
      const ul = document.getElementById("memory-list");
      ul.innerHTML = "";
      data.forEach(ani => {
        const li = document.createElement("li");
        li.innerHTML = `
          ${ani.icerik}
          <button onclick="sil(${ani.id})">🗑️</button>
        `;
        ul.appendChild(li);
      });
    });
}

function sil(id) {
  const kullanici_id = "admin"; // veya localStorage'dan al
  fetch(`http://127.0.0.1:5000/memory/delete/${id}?kullanici_id=${kullanici_id}`, {
    method: "DELETE"
  })
  .then(res => res.json())
  .then(data => {
    alert(data.durum || data.hata || "Silindi");
    listele();
  });
}


function filtrele() {
  fetch("http://127.0.0.1:5000/memory/filter", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ kullanici_id: "admin" })
  })
  .then(res => res.json())
  .then(data => {
    const ul = document.getElementById("memory-list");
    ul.innerHTML = "";
    data.forEach(ani => {
      const li = document.createElement("li");
      li.innerHTML = `
        ${ani.icerik}
        <button onclick="sil(${ani.id})">🗑️</button>
      `;
      ul.appendChild(li);
    });
  });
}

function tumunuSil() {
  fetch("http://127.0.0.1:5000/memory/delete_all", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ kullanici_id: "admin" })
  })
  .then(res => res.json())
  .then(data => {
    alert(data.message || "Tüm bellek temizlendi");
    listele();
  });
}

window.onload = function() {
  listele();
};


function guncelle() {
  const id = document.getElementById("guncelleId").value;
  const metin = document.getElementById("yeniMetin").value;
  const kullanici_id = localStorage.getItem("kullanici_id") || "admin"; // varsayılan admin

  fetch(`http://127.0.0.1:5000/memory/update/${id}?kullanici_id=${kullanici_id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ metin })
  })
  .then(res => res.json())
  .then(data => {
    alert(data.durum || data.hata);
    listele();
  });
}
document.getElementById("clear-memory").addEventListener("click", () => {
    if (confirm("Otomatik verileri silmek istediğinizden emin misiniz?")) {
        sendMemoryCommand("/memory/clear");
    }
});

document.getElementById("delete-all-memory").addEventListener("click", () => {
    if (confirm("Tüm verileri silmek istediğinizden emin misiniz?")) {
        sendMemoryCommand("/memory/delete_all");
    }
});
