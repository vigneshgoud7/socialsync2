document.addEventListener("DOMContentLoaded", () => {

  const form = document.getElementById("loginForm");
  const idInput = document.getElementById("identifier");
  const password = document.getElementById("password");
  const toggle = document.getElementById("togglePassword");
  const errorMsg = document.getElementById("error-msg");
  const btn = document.getElementById("loginBtn");
  const spinner = btn.querySelector(".spinner");
  const overlay = document.getElementById("successOverlay");

  toggle.addEventListener("click", () => {
    password.type = password.type === "password" ? "text" : "password";
    toggle.innerText = password.type === "password" ? "Show" : "Hide";
  });

  function setLoading(v){
    if(v){ btn.classList.add("loading"); spinner.style.display="inline-block"; }
    else { btn.classList.remove("loading"); spinner.style.display="none"; }
  }

  form.addEventListener("submit", async e => {
    e.preventDefault();
    errorMsg.style.display="none";
    form.classList.remove("shake");

    if(!idInput.value.trim() || !password.value.trim()){
      errorMsg.innerText = "Please fill all fields.";
      errorMsg.style.display="block";
      form.classList.add("shake");
      return;
    }

    setLoading(true);

    try{
      const res = await fetch("http://127.0.0.1:8000/login", {
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({
          identifier: idInput.value.trim(),
          password: password.value.trim()
        })
      });

      const data = await res.json();
      await new Promise(r => setTimeout(r, 500));

      if(!res.ok){
        errorMsg.innerText = data.detail || "Login failed.";
        errorMsg.style.display="block";
        form.classList.add("shake");
        setLoading(false);
        return;
      }

      localStorage.setItem("token", data.access_token);
      overlay.classList.add("show");
      setTimeout(()=> location.replace("home.html"), 800);

    } catch {
      errorMsg.innerText = "Server error. Try again.";
      errorMsg.style.display="block";
      form.classList.add("shake");
      setLoading(false);
    }
  });

});
