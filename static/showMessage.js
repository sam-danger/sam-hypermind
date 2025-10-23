function showMessage(msg) {
    const box = document.createElement("div");
    box.innerText = msg;
    box.style.position = "fixed";
    box.style.bottom = "20px";
    box.style.left = "50%";
    box.style.transform = "translateX(-50%)";
    box.style.background = "#111";
    box.style.color = "#fff";
    box.style.padding = "12px 20px";
    box.style.borderRadius = "10px";
    box.style.boxShadow = "0 0 10px #00ffff";
    box.style.zIndex = 99999;
    box.style.fontSize = "14px";
    box.style.fontFamily = "Arial, sans-serif";
    document.body.appendChild(box);
    setTimeout(() => box.remove(), 3000);
}
