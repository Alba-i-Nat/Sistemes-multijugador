# Sistemes Multijugador - Pràctica 1

Petit projecte de sistema d'autenticació amb PHP, HTML, CSS i JavaScript.

## Característiques

- **Registre d'usuaris** amb validació de contrasenyes
- **Inici de sessió** amb credencials segures
- **Manteniment de sessió** amb cookies
- **Recuperació d'accés** via correu electrònic
- **Validació amb Pwned Passwords** (client i servidor)
- **Contrasenyes hashejades** amb bcrypt i sal
- **Protecció CAPTCHA** o verificació pre-registre

## Instal·lació

1. Descarrega PHP (VS16 x64 Thread Safe) i descomprimeix-lo a la carpeta `PHP/`
2. Crea la base de dades:
   ```bash
   private/create_db.cmd
   ```
3. Inicia el servidor de desenvolupament:
   ```bash
   private/start_devserver.cmd
   ```
4. Obre el navegador a `http://localhost:8000`

## Estructura del projecte

```
├── assets/                 # Assets del projecte
├── PHP/                    # Carpeta per PHP descomprimit
├── private/
│   ├── create_db.cmd       # Script per crear la BD
│   ├── start_devserver.cmd # Script per iniciar servidor
│   └── *.html              # Plantilles HTML
└── public/
    ├── mvp.css             # Estils base
    ├── index.php           # Pàgina principal
    ├── el_meu.js           # Codi JavaScrpt personalitzat
    └── el_meu.css          # Estils personalitzats
```

## Seguretat

- Contrasenyes amb longitud mínima
- Hash bcrypt amb sal
- Cookies amb flags `SameSite`, `Secure` i `HttpOnly`
- Validació client i servidor
- Protecció contra atacs de força bruta

## Autors

Alba Agustí i Natalya Golembyovska
