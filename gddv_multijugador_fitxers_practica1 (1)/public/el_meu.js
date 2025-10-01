// Afegeix aquí el teu codi JavaScript
document.addEventListener("DOMContentLoaded", () => {
    const toggles = [
        { input: "register_password", toggle: "toggle_register_pw" },
        { input: "login_password", toggle: "toggle_login_pw" }
    ];

    toggles.forEach(({input, toggle}) => {
        const inp = document.getElementById(input);
        const eye = document.getElementById(toggle);
        if (inp && eye) {
            eye.addEventListener("click", () => {
                if (inp.type === "password") {
                    inp.type = "text";
                    eye.textContent = "◡";
                } else {
                    inp.type = "password";
                    eye.textContent = "⬤";
                }
            });
        }
    });
});