document.addEventListener("DOMContentLoaded", () => {

  const form = document.getElementById("signupForm");
  const fullname = document.getElementById("fullname");
  const username = document.getElementById("username");
  const email = document.getElementById("email");
  const phone = document.getElementById("phone");
  const password = document.getElementById("signupPassword");
  const toggle = document.getElementById("toggleSignupPw");
  const errorMsg = document.getElementById("signup-error");
  const btn = document.getElementById("signupBtn");
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

    if(!fullname.value.trim() || !username.value.trim() ||
       !email.value.trim() || !phone.value.trim() || !password.value.trim()){
      errorMsg.innerText = "Please fill all fields.";
      errorMsg.style.display="block";
      form.classList.add("shake");
      return;
    }

    if(password.value.length < 6){
      errorMsg.innerText = "Password must be at least 6 characters.";
      errorMsg.style.display="block";
      form.classList.add("shake");
      return;
    }

    setLoading(true);

    try{
      const res = await fetch("http://127.0.0.1:8000/signup",{
        method:"POST",
        headers:{ "Content-Type":"application/json" },
        body: JSON.stringify({
          fullname: fullname.value.trim(),
          username: username.value.trim(),
          email: email.value.trim(),
          phone: phone.value.trim(),
          password: password.value.trim()
        })
      });

      const data = await res.json();
      await new Promise(r=>setTimeout(r,500));

      if(!res.ok){
        errorMsg.innerText = data.detail || "Signup failed.";
        errorMsg.style.display="block";
        form.classList.add("shake");
        setLoading(false);
        return;
      }

      overlay.classList.add("show");
      setTimeout(()=> location.replace("login.html"), 1000);

    } catch {
      errorMsg.innerText = "Server error. Try again.";
      errorMsg.style.display="block";
      form.classList.add("shake");
      setLoading(false);
    }

  });

});
