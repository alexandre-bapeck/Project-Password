import string
import random
import hashlib
import pyperclip
import dearpygui.dearpygui as gui
import json
import datetime

from dearpygui.demo import show_demo


def GenerateStrongPassword(length=16):
    character_set = (
            string.ascii_uppercase +
            string.ascii_lowercase +
            string.digits +
            string.digits+
            string.punctuation
    )
    password = ''.join(random.choices(character_set, k=length))
    return password


def CheckPassWordStrenght(password):
    if len(password) < 16:
        return "Le mot de passe doit comporter au moins 16 caractères.", (255, 0, 0)

    if not any(char.isupper() for char in password):
        return "Le mot de passe doit contenir au moins une majuscule.", (255, 0, 0)

    if not any(char.isdigit() for char in password):
        return "Le mot de passe doit contenir au moins un chiffre.", (255, 0, 0)

    special_characters = string.punctuation
    if not any(char in special_characters for char in password):
        return "Le mot de passe doit contenir au moins un caractère spécial.", (255, 0, 0)

    return "Mot de passe valide !", (0, 255, 0)


def GenerateAndSetPassword():
    current_date_time = datetime.datetime.now()
    new_password = GenerateStrongPassword()
    pyperclip.copy(new_password)
    gui.set_value("password", new_password)
    encrypted_password = hashlib.sha256(new_password.encode()).hexdigest()

    try:
        with open("password_history.json", "r") as file:
            passwords_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        passwords_data = {}

    date_key = current_date_time.strftime("%Y-%m-%d")

    if date_key not in passwords_data:
        passwords_data[date_key] = []

    passwords_data[date_key].append({
        "password": new_password,
        "sha256": encrypted_password,
        "timestamp": current_date_time.isoformat()
    })

    with open("password_history.json", "w") as file:
        json.dump(passwords_data, file, indent=4)

    strength_message, color = CheckPassWordStrenght(new_password)
    gui.set_value("password_strength", strength_message)
    gui.configure_item("password_strength", color=color)

    ShowPasswordHistory()


def CopyPassword(sender, app_data, user_data):
    current_password = gui.get_value("password")
    if current_password:
        pyperclip.copy(current_password)
        gui.set_value("status", "Mot de passe copié !")


def ShowPasswordHistory():

    if gui.does_item_exist("history_container"):
        gui.delete_item("history_container")


    with gui.group(tag="history_container", parent="Primary Window"):
        try:
            with open("password_history.json", "r") as file:
                passwords_data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            passwords_data = {}

        if not passwords_data:
            gui.add_text("Aucun historique de mot de passe")
        else:
            for date_key, passwords in reversed(list(passwords_data.items())):
                gui.add_text(f"Date: {date_key}", color=(0, 100, 255))
                for json_data in passwords:
                    gui.add_text(f"Mot de passe: {json_data['password']}")
                    gui.add_text(f"SHA256: {json_data['sha256']}")
                    gui.add_text(f"Timestamp: {json_data['timestamp']}")
                gui.add_separator()



def MainWindow():
    with gui.font_registry():
        default_font = gui.add_font("JetBrainsMono-SemiBold.ttf", 16)
    with gui.window(tag="Primary Window", width=600, height=800):
        gui.bind_font(default_font)
        gui.add_text("Générateur de Mot de Passe")

        gui.add_input_text(
            tag="password",
            label="Mot de passe généré",
            width=300,
            readonly=True
        )

        with gui.group(horizontal=True):
            gui.add_button(
                label="Générer Mot de Passe",
                callback=GenerateAndSetPassword
            )
            gui.add_button(
                label="Copier",
                callback=CopyPassword
            )

        gui.add_button(
            label="Afficher l'historique des mots de passe",
            callback=ShowPasswordHistory
        )

        gui.add_text(tag="password_strength", default_value="")
        gui.add_text(tag="status", default_value="")





def main():
    gui.create_context()
    gui.create_viewport(title="Générateur de Mot de Passe", width=600, height=800)
    print(string.digits)
    MainWindow()

    gui.setup_dearpygui()
    gui.show_viewport()
    gui.start_dearpygui()
    gui.destroy_context()


if __name__ == "__main__":
    main()