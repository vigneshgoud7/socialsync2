const translations = {
  en:{ 
    loginTitle:"Welcome Back",
    loginSubtitle:"Please enter your details to login.",
    identifier:"Email, username or phone",
    password:"Password",
    loginBtn:"Login",
    signupTitle:"Create Account",
    signupSubtitle:"Fill in the details to sign up",
    fullname:"Full name",
    username:"Username",
    email:"Email",
    phone:"Phone",
    signupBtn:"Sign Up"
  },
  es:{ 
    loginTitle:"Bienvenido de nuevo",
    loginSubtitle:"Ingrese sus datos para iniciar sesión.",
    identifier:"Correo, usuario o teléfono",
    password:"Contraseña",
    loginBtn:"Iniciar sesión",
    signupTitle:"Crear cuenta",
    signupSubtitle:"Complete los datos para registrarse.",
    fullname:"Nombre completo",
    username:"Usuario",
    email:"Correo",
    phone:"Teléfono",
    signupBtn:"Registrarse"
  },
  fr:{ 
    loginTitle:"Bon retour",
    loginSubtitle:"Veuillez entrer vos informations pour vous connecter.",
    identifier:"Email, utilisateur ou téléphone",
    password:"Mot de passe",
    loginBtn:"Connexion",
    signupTitle:"Créer un compte",
    signupSubtitle:"Remplissez les informations pour vous inscrire.",
    fullname:"Nom complet",
    username:"Nom d'utilisateur",
    email:"Email",
    phone:"Téléphone",
    signupBtn:"S'inscrire"
  }
};


function applyLanguage(lang){
  const t = translations[lang] || translations.en;

  // LOGIN PAGE
  if (document.getElementById("loginTitle")) {
    document.getElementById("loginTitle").innerText = t.loginTitle;
    document.getElementById("loginSubtitle").innerText = t.loginSubtitle;
    document.getElementById("label-identifier").innerText = t.identifier;
    document.getElementById("label-password").innerText = t.password;
    document.querySelector("#loginBtn .label").innerText = t.loginBtn;
  }

  // SIGNUP PAGE
  if (document.getElementById("signupTitle")) {
    document.getElementById("signupTitle").innerText = t.signupTitle;
    document.getElementById("signupSubtitle").innerText = t.signupSubtitle;
    document.getElementById("label-fullname").innerText = t.fullname;
    document.getElementById("label-username").innerText = t.username;
    document.getElementById("label-email").innerText = t.email;
    document.getElementById("label-phone").innerText = t.phone;
    document.querySelector("#signupBtn .label").innerText = t.signupBtn;
  }
}


document.addEventListener("DOMContentLoaded", ()=>{
  const loginSel = document.getElementById("language");
  const signupSel = document.getElementById("language-signup");

  if (loginSel) {
    loginSel.addEventListener("change", e => applyLanguage(e.target.value));
    applyLanguage(loginSel.value);
  }

  if (signupSel) {
    signupSel.addEventListener("change", e => applyLanguage(e.target.value));
    applyLanguage(signupSel.value);
  }
});
