import base64
import tkinter as tk
from tkinter import *
from tkinter import font
from tkinter import filedialog


def popup():
    """ Pop Up function for Creating a new window for brute force"""
    # Creating the window
    info = tk.Tk()
    info.geometry('500x700+750+50')
    info.title('Brute Force')

    # Creating the input text decoded
    text_decoded = tk.Label(info, text="Enter Decoded Text :",
                            font="Aharoni 13 bold")
    text_decoded.pack(padx=10, pady=10)

    input_decoded = tk.Text(info, bg='#DB7093', font="Tahoma 10",
                            width=45, height=2)
    input_decoded.pack()

    # Creating the input text encrypted
    text_encrypted = tk.Label(info, text="Enter Encrypted Text :",
                              font="Aharoni 13 bold")
    text_encrypted.pack(padx=10, pady=10)

    input_encrypted = tk.Text(info, bg='#DB7093',
                              font="Tahoma 10", width=45, height=2)
    input_encrypted.pack()

    # Creating the Buttons Choose Options For file
    label_frame = LabelFrame(info, font="Aharoni 12 bold",
                             text='Choose Options For file :')
    label_frame.pack(padx=15, pady=15)

    btn_force_file = tk.Button(label_frame,
                               text="Try Force to File",
                               font="Aharoni 12 bold",
                               width=15,
                               height=1,
                               bg="#000",
                               fg="#fff",
                               command=lambda: force_options(input_decoded,
                                                             input_encrypted,
                                                             "bruteforce-file",
                                                             label_res))
    btn_force_file.pack(padx=5, pady=5)

    btn_dec_file = tk.Button(label_frame,
                             text="Decoded Text From File",
                             font="Aharoni 12 bold",
                             width=20,
                             height=1,
                             bg="#000", fg="#fff",
                             command=lambda: from_file(input_decoded,
                                                       label_res))
    btn_dec_file.pack(side=LEFT, padx=5, pady=5)

    btn_enc_file = tk.Button(label_frame,
                             text="Encrypted Text From File",
                             font="Aharoni 12 bold",
                             width=20,
                             height=1,
                             bg="#000", fg="#fff",
                             command=lambda: from_file(input_encrypted,
                                                       label_res))
    btn_enc_file.pack(side=RIGHT, padx=5, pady=5)

    # Creating the Button for brute force fnc
    tk.Button(info, text='Try Force', font="Aharoni 12 bold",
              bg="#000", fg="#fff",
              command=lambda: force_options(input_decoded,
                                            input_encrypted,
                                            "brute-force",
                                            label_res)).pack(padx=10, pady=10)

    # Creating the Label for the key result from brute force fnc
    text_res = tk.Label(info, text="The Key is :", font="Aharoni 13 bold")
    text_res.pack(padx=10, pady=10)

    label_res = tk.Label(info, text="", bg='#DB7093', font="Aharoni 13",
                         width=45, height=15)
    label_res.pack()

    # Creating the Button for Close the window
    tk.Button(info, text='Close', bg="#000", fg="#fff",
              font="Aharoni 12 bold", width=7, height=1,
              command=info.destroy).pack(padx=10, pady=10)


def brute_force(message_d, message_e):
    """ brute force function for Searching a key by encrypted
     text and decrypted text or a hint"""
    message_e = str(message_e).replace("\n", "").strip()
    message_d = str(message_d).replace("\n", "").strip()

    key_num = 1
    status = False
    res_msg = ""
    # Search the key by getting Decoded text and Encrypted text or hint
    while not key_num == 900000:
        res_text = decrypt(message_e, str(key_num) + "\n")
        if message_d in res_text:
            res_msg = "The key is --> " + str(key_num) + " <-- " + \
                      "Found - " + res_text + "\n"
            status = True
        key_num = key_num + 1
    if not status:
        res_msg = "the key is Not Found"

    return res_msg


def encrypt(user_text, user_key):
    """encrypt function to encrypt the text user Base64 Vigenère cipher """
    NUM_MOD = 385
    res_enc = []
    user_text = str(user_text).replace("\n", "")

    for i in range(len(user_text)):
        temp_key = user_key[i % len(user_key)]
        temp_enc = chr((ord(user_text[i]) +
                        ord(temp_key)) % NUM_MOD)
        res_enc.append(temp_enc)
    return base64.urlsafe_b64encode("".join(res_enc).encode()).decode()


def decrypt(user_text, user_key):
    """decrypt function to decrypt the text Base64 Vigenère cipher """
    NUM_MOD = 385
    res_dec = []
    user_text = str(user_text).replace("\n", "")
    try:
        user_text = base64.urlsafe_b64decode(user_text).decode()
    except:
        user_text = str(user_text).replace("\n", "")

    for i in range(len(user_text)):
        temp_key = user_key[i % len(user_key)]
        temp_dec = chr((NUM_MOD + ord(user_text[i]) -
                        ord(temp_key)) % NUM_MOD)
        res_dec.append(temp_dec)
    return "".join(res_dec)


def enc_options(text_input, key_input, option, result):
    """function for Check the user Choose of encrypt options and
     Activate the appropriate function"""

    user_text = text_input.get("1.0", "end")
    key = key_input.get("1.0", "end")
    user_text = str(user_text).replace("\n", "").strip()

    try:
        # Messages to the user about empty input
        if int(key) < 0:
            result["text"] = "Try again, Please Enter Key only" \
                             " positive numbers"
            return
        if len(user_text) < 1:
            result["text"] = "Try again, Please Enter text "
            return
        # encrypting the text by the encrypt fnc
        if option == 'Encrypt':
            result["text"] = encrypt(user_text, key)
        # encrypting the text by the encrypt fnc to file
        elif option == 'Enc-to-file':
            f = filedialog.asksaveasfile(mode='w', defaultextension=".txt")
            if f is None:
                result["text"] = "Failed, The file was not created"
                return

            res_msg = encrypt(user_text, key)
            f.write(res_msg)
            f.close()
            result["text"] = "The file was created successfully"
    except:
        result["text"] = "Try again, try Entering text and key " + \
                         "\n" + "the key will contain only numbers"


def dec_options(text_input, key_input, option, result):
    """function for Check the user Choose of decrypt options
    and Activate the appropriate function"""

    user_text = text_input.get("1.0", "end")
    key = key_input.get("1.0", "end")
    user_text = str(user_text).replace("\n", "").strip()

    try:
        # Messages to the user about incorrect and empty input
        if int(key) < 0:
            result["text"] = "Try again, Please Enter Key only" \
                             " positive numbers"
            return
        if len(user_text) < 1:
            result["text"] = "Try again, Please Enter text "
            return
        # deciphering the text by the decrypt fnc
        if option == 'Decrypt':
            result["text"] = decrypt(user_text, key)
        # deciphering the text by the decrypt fnc to file
        elif option == 'Dec-to-file':
            f = filedialog.asksaveasfile(mode='w', defaultextension=".txt")
            if f is None:
                result["text"] = "Failed, The file was not created"
                return

            res_msg = decrypt(user_text, key)
            f.write(res_msg)
            f.close()
            result["text"] = "The file was created successfully"
    except:
        result["text"] = "Try again, try Entering text and key " + \
                         "\n" + "the key will contain only numbers"


def force_options(text_dec, text_enc, option, result):
    """function for Check the user Choose of force options
    and Activate the appropriate function"""

    text_dec = text_dec.get("1.0", "end")
    text_enc = text_enc.get("1.0", "end")
    text_dec = str(text_dec).replace("\n", "").strip()
    text_enc = str(text_enc).replace("\n", "").strip()

    # Messages to the user about empty input
    if len(text_dec) < 1 and len(text_enc) < 1:
        result["text"] = "Try again, Enter Decoded and Encrypted text"
        return
    elif len(text_dec) < 1:
        result["text"] = "Try again, Enter Decoded text"
        return
    elif len(text_enc) < 1:
        result["text"] = "Try again, Enter Encrypted text"
        return

    # force the text by the brute_force fnc
    if option == 'brute-force':
        result["text"] = brute_force(text_dec, text_enc)
    # force the text by the brute_force fnc to file
    elif option == 'bruteforce-file':
        f = filedialog.asksaveasfile(mode='w', defaultextension=".txt")
        if f is None:
            result["text"] = "Failed, The file was not created"
            return

        res_msg = brute_force(text_dec, text_enc)
        f.write(res_msg)
        print(res_msg)
        f.close()
        result["text"] = "The file was created successfully"


def from_file(text, result):
    """function for Select text from file by filedialog"""
    root = tk.Tk()
    root.withdraw()

    try:
        file_path = filedialog.askopenfilename()
        f = open(file_path, "r")
        text.delete("1.0", "end")
        text.insert("1.0", f.read())
        result["text"] = ""
    except:
        result["text"] = "The file was not selected"


def main():
    """main function - It contains all the settings of the program"""

    # Creating the window
    root = tk.Tk()
    root.geometry("650x700+50+50")
    root.title("Tslil Aharon - Final Project")
    root.configure(bg='#eee')

    # Creating the font
    font_title = font.Font(family="Berlin Sans FB Demi", size=13)
    font_regular = font.Font(family="Tahoma", size=10)
    font_btn = font.Font(family="Aharoni", size=12, weight="bold")

    # Creating the menu
    menubutton = Menubutton(root, text="Menu",
                            foreground='#000', font=font_btn)
    menubutton.menu = Menu(menubutton)
    menubutton["menu"] = menubutton.menu

    menubutton.menu.add_command(label="Encrypt", background='#DB7093',
                                foreground='#fff', font=font_btn,
                                command=lambda: enc_options(text_input,
                                                            key_input,
                                                            "Encrypt",
                                                            result))
    menubutton.menu.add_command(label="Decrypt", background='#DB7093',
                                foreground='#fff', font=font_btn,
                                command=lambda: dec_options(text_input,
                                                            key_input,
                                                            "Decrypt",
                                                            result))
    menubutton.menu.add_command(label="Text From File", background='#DB7093',
                                foreground='#fff', font=font_btn,
                                command=lambda: from_file(text_input,
                                                          result))
    menubutton.menu.add_command(label="Encrypt to file", background='#DB7093',
                                foreground='#fff', font=font_btn,
                                command=lambda: enc_options(text_input,
                                                            key_input,
                                                            "Enc-to-file",
                                                            result))
    menubutton.menu.add_command(label="Decrypt to file", background='#DB7093',
                                foreground='#fff', font=font_btn,
                                command=lambda: dec_options(text_input,
                                                            key_input,
                                                            "Dec-to-file",
                                                            result))
    menubutton.menu.add_command(label="Brute Force", background='#000',
                                foreground='#DB7093', font=font_btn,
                                command=lambda: popup())
    menubutton.menu.add_command(label="Exit", background='#DB7093',
                                foreground='#fff', font=font_btn,
                                command=lambda: exit())
    menubutton.pack(padx=5, pady=5)

    # Creating the input text
    text_label = tk.Label(text="Enter Text :", font=font_title)
    text_label.pack()

    text_input = tk.Text(root, font=font_regular, bg='#DB7093',
                         width=45, height=2)
    text_input.pack(padx=10, pady=10)

    kye_label = tk.Label(text="Enter Key :", font=font_title)
    kye_label.pack()

    key_input = tk.Text(root, font=font_regular, bg='#DB7093',
                        width=45, height=2)
    key_input.pack(padx=10, pady=10)

    # Creating the Encrypt or Decrypt Buttons
    # adding a labelframe to the window
    choose_labelframe = LabelFrame(root, font=font_title,
                                   text='Choose to Encrypt or Decrypt :')
    choose_labelframe.pack(padx=15, pady=15)

    btn_encrypt = tk.Button(choose_labelframe,
                            text='Encrypt',
                            bg="#000",
                            fg="#fff",
                            font=font_btn,
                            width=10,
                            height=1,
                            command=lambda: enc_options(text_input,
                                                        key_input,
                                                        "Encrypt",
                                                        result))
    btn_encrypt.pack(side=LEFT, padx=5, pady=10)

    btn_decrypt = tk.Button(choose_labelframe,
                            text="Decrypt",
                            font=font_btn,
                            bg="#000",
                            fg="#fff",
                            width=10,
                            height=1,
                            command=lambda: dec_options(text_input,
                                                        key_input,
                                                        "Decrypt",
                                                        result))
    btn_decrypt.pack(side=RIGHT, padx=5, pady=10)

    # Creating the Encrypt or Decrypt Buttons from or to file
    # adding a labelframe
    file_labelframe = LabelFrame(root, font=font_title,
                                 text='Choose Options For file :')
    file_labelframe.pack(padx=15, pady=15)

    btn_from_file = tk.Button(file_labelframe,
                              text="Text From File",
                              font=font_btn,
                              width=12,
                              height=1,
                              bg="#000", fg="#fff",
                              command=lambda: from_file(text_input, result))
    btn_from_file.pack(padx=5, pady=10)

    btn_encrypt_file = tk.Button(file_labelframe,
                                 text="Encrypt to File",
                                 font=font_btn,
                                 width=12,
                                 height=1,
                                 bg="#000",
                                 fg="#fff",
                                 command=lambda: enc_options(text_input,
                                                             key_input,
                                                             "Enc-to-file",
                                                             result))
    btn_encrypt_file.pack(side=LEFT, padx=5, pady=5)

    btn_decrypt_file = tk.Button(file_labelframe,
                                 text="Decrypt to File",
                                 font=font_btn,
                                 width=12,
                                 height=1,
                                 bg="#000",
                                 fg="#fff",
                                 command=lambda: dec_options(text_input,
                                                             key_input,
                                                             "Dec-to-file",
                                                             result))
    btn_decrypt_file.pack(side=RIGHT, padx=5, pady=5)

    # Creating the Result Label
    label_result = tk.Label(text="The Result is :", font=font_title)
    label_result.pack(padx=10, pady=10)

    result = tk.Label(text="", font=font_title, bg='#DB7093',
                      width=60, height=4)
    result.pack(pady=10)

    # Creating the brute force Button
    btn_brute_force = tk.Button(root, text='Brute Force',
                                font=font_btn, bg="#000", fg="#DB7093",
                                width=12, height=1, command=popup)
    btn_brute_force.pack(padx=10, pady=10)

    # Creating the exit Button
    btn_exit = tk.Button(root, text='Exit', font=font_btn, width=8,
                         height=1, bg="#000", fg="#fff", command=exit)
    btn_exit.pack(padx=10, pady=10)

    tk.mainloop()


if __name__ == "__main__":
    main()
