_EXAMPLE OF APP-___________________________________________________________________________________________________________________________________________
![example 2 cipher](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/60997b4e-65af-4b43-9a7b-b8bf32baa02d)

Greetings,

I'm excited to introduce the Vigenere Cipher Application, a testament to my dedication to cybersecurity innovation. Crafted with precision in Python, this tool caters to the diverse needs of cybersecurity professionals, employers, and GitHub users alike. Initially conceived to decode Caesar ciphers, my journey through research and development has led me to recognize the limitations of simplistic encryption methods.

Here are some key points about my project:

- **Innovative Transformation**: From its humble origins decoding Caesar ciphers, my application has evolved into a robust encryption tool powered by the Vigenere cipher. This transformation underscores my unwavering commitment to fortifying digital defenses.

- **Continuous Learning**: With each line of code meticulously crafted and every debugging session navigated, my understanding of cybersecurity principles has deepened. This project has provided invaluable opportunities for learning and growth.

- **Professional Development**: For cybersecurity professionals, this application serves as an invaluable asset, offering a platform to expand their skill set and stay ahead of evolving threats. It's a tool designed to empower professionals in their quest for cybersecurity excellence.

- **Organizational Security**: Employers seeking to bolster their organization's security posture will find in this application a reliable ally in the ongoing battle against cyber adversaries. It's a proactive step towards safeguarding digital assets and maintaining a strong security posture.

- **Educational Resource**: Even for GitHub users curious about encryption algorithms, my project serves as an educational resource, providing insights into the complexities of cybersecurity. It's a journey of discovery and enlightenment for enthusiasts of all levels.

Pros:

    Robust Encryption: The application utilizes the Vigenere cipher, a more complex encryption method compared to the simplistic Caesar cipher, providing stronger security for sensitive information.

    Educational Value: It serves as an educational resource for cybersecurity enthusiasts, offering insights into encryption algorithms and practical experience in implementing them.

    Versatility: The application caters to a diverse audience, including cybersecurity professionals, employers, and GitHub users, addressing their specific needs and interests.

    Professional Development: For cybersecurity professionals, it offers an opportunity for skill enhancement and professional development by providing hands-on experience with encryption tools.

    Enhanced Security: Employers can utilize the application to bolster their organization's security posture, ensuring better protection of digital assets and sensitive data.

Cons:

    Limited Encryption Scope: While the Vigenere cipher provides stronger encryption compared to the Caesar cipher, it may still have limitations in highly advanced threat scenarios or against sophisticated attackers.

    Learning Curve: Users unfamiliar with encryption algorithms may face a learning curve when using the application, requiring time and effort to understand its functionalities and implementation.

    Potential Vulnerabilities: Like any software application, there may be potential vulnerabilities or bugs in the code that could be exploited by attackers if not addressed through rigorous testing and updates.

(Example_step (1) 

[3 generation messages]

E7939NlheaAzr6R

![ciper exampl 3](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/8db3a867-9981-4774-a194-85a4c3fb6bd6)

rHsTNm3o4WIaQjr

![cipher example 5](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/0afee446-776f-4a28-8708-4d9cb41e5058)

UiCbVUdnEE6sG09

![cipher example 6](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/bd503ce7-e512-4f32-b850-c5c67481d8e6)

(Example_step (2) 

[3 generation Keywords]

eXtQewkvMNdy7Sl

![example 7 cipher](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/2155d9d5-8a4c-42be-a5f6-306d9166614a)

fS5Nl9vE3vRNl70

![cipher examplke 8](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/6d23f4b9-138d-40c2-9880-e0eb8597da66)

CY7eQ6iEBpmPpQH

![cipher examplke 9](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/a3cdd86c-e9d6-4f55-9295-dc433964ef44)

(Example_step (3) 

[3 generation Results:

E7939NlheaAzr6R+
eXtQewkvMNdy7Sl=
----------------
Result:Encyypt<

B4606SpeomDwg3W

![cipher example 10](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/20efb163-c742-4f8e-b1ce-f0e24ad55446)

rHsTNm3o4WIaQjr+
fS5Nl9vE3vRNl70=

----------------
Result:Encyypt<

pMtTRr6c1SGfRjv

![cipher example 12](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/dc48b5cc-39e6-47fe-84cf-227d161bcb3b)

UiCbVUdnEE6sG09+
CY7eQ6iEBpmPpQH=

----------------
Result:Encyypt<

JtFyYWeeSM3pJ66

![cipher example big one](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/58a36319-1784-4850-b28d-ec90854c945e)

Example(clear)

![example 56](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/53f99af5-65e1-4979-8adb-b345a4f205dd)

(Last Example Decryption){4}

UiCbVUdnEE6sG09+
eXtQewkvMNdy7Sl=
----------------
Result:Decrypt<

XyQyYFazFE9nC32

![Lastone cipher](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/5b1de23e-2e99-4e33-8299-b1e355b819bf)

# If you made it this Far  Goodluck and stay safe 

![cat art](https://github.com/Kad3n13/VigenereCipherApp/assets/159424810/487f94ba-95ac-4169-8ab7-40736dd4b21d)

# (CODE!!!)
mport tkinter as tk
from tkinter import messagebox, filedialog
import random
import string

# Constants
RECOMMENDED_KEYWORD_LENGTH = 15

# Logic Functions
def generate_random_key(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_random_keyword(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def vigenere_cipher(text, keyword, mode):
    result = ''
    keyword_index = 0
    for char in text:
        key_char = keyword[keyword_index % len(keyword)]
        if char.isalpha():
            base = 65 if char.isupper() else 97
            shift = ord(key_char) % 26
            if mode == 'Encrypt':
                encrypted_unicode = (ord(char) - base + shift) % 26 + base
                result += chr(encrypted_unicode)
            elif mode == 'Decrypt':
                decrypted_unicode = (ord(char) - base - shift + 26) % 26 + base
                result += chr(decrypted_unicode)
            keyword_index += 1
        elif char.isdigit():
            while not key_char.isdigit():
                keyword_index += 1
                key_char = keyword[keyword_index % len(keyword)]
            shift = int(key_char) % 10
            if mode == 'Encrypt':
                encrypted_digit = (int(char) + shift) % 10
            elif mode == 'Decrypt':
                encrypted_digit = (int(char) - shift + 10) % 10
            result += str(encrypted_digit)
            keyword_index += 1
        else:
            result += char
    return result

# GUI Application
class VigenereCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersecurity Vigenere Cipher")
        self.root.configure(bg="#0F0F0F")  # Dark background
        self.create_widgets()

        # ASCII art of the cat
        self.cat_art = '''
  /\_/\   (0)|)
 ( o.o ) |0|||
> ^ < |0| /
 /  |\|/ /||
/..-.-| / /
\.../---|- 
|E|  -
--  |N|   -
    -- - |C|
     |R| --
|Y|  -- -
--    |P|  -
      - --|T|
 -   |I|  --
|O|  --
--  |N|
   \ - '''
        # Create a label to display the ASCII art in the background
        self.cat_label = tk.Label(self.root, text=self.cat_art, font=("Courier", 40), bg="#0F0F0F", fg="#00FF00")
        self.cat_label.place(relx=0.5, rely=0.5, anchor="center")

    def create_widgets(self):
        # Choose Operation Label and Radio Buttons
        self.operation_label = tk.Label(self.root, text="Choose Operation (Encrypt/Decrypt):", bg="#0F0F0F", fg="#00FF00", font=("Courier", 12, "bold"))
        self.operation_label.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="w")
        self.operation_label.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        self.operation_var = tk.StringVar(value="Encrypt")

        self.encrypt_radio = tk.Radiobutton(self.root, text="Encrypt", variable=self.operation_var, value="Encrypt", bg="#0F0F0F", fg="#00FF00", font=("Courier", 10))
        self.encrypt_radio.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.encrypt_radio.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        self.decrypt_radio = tk.Radiobutton(self.root, text="Decrypt", variable=self.operation_var, value="Decrypt", bg="#0F0F0F", fg="#00FF00", font=("Courier", 10))
        self.decrypt_radio.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        self.decrypt_radio.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        # Message Label and Entry
        self.message_label = tk.Label(self.root, text="Enter Message (Max 15 characters):", bg="#0F0F0F", fg="#00FF00", font=("Courier", 12, "bold"))
        self.message_label.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="w")
        self.message_label.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        self.message_text = tk.Entry(self.root, bg="#333333", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 10))
        self.message_text.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="we")
        self.message_text.config(validate="key", validatecommand=(self.root.register(self.validate_text), "%P"))
        self.message_text.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        # Keyword Label and Entry
        self.keyword_label = tk.Label(self.root, text="Enter Keyword (Max 15 characters):", bg="#0F0F0F", fg="#00FF00", font=("Courier", 12, "bold"))
        self.keyword_label.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="w")
        self.keyword_label.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        self.keyword_entry = tk.Entry(self.root, bg="#333333", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 10))
        self.keyword_entry.grid(row=5, column=0, columnspan=3, padx=10, pady=10, sticky="we")
        self.keyword_entry.config(validate="key", validatecommand=(self.root.register(self.validate_text), "%P"))
        self.keyword_entry.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        # Result Label and Text
        self.result_label = tk.Label(self.root, text="Result:", bg="#0F0F0F", fg="#00FF00", font=("Courier", 12, "bold"))
        self.result_label.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="w")
        self.result_label.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        self.result_text = tk.Text(self.root, bg="#333333", fg="#FFFFFF", font=("Courier", 10), height=1, width=30)
        self.result_text.grid(row=7, column=0,

        columnspan=3, padx=10, pady=10, sticky="we")
        self.result_text.config(state=tk.DISABLED)
        self.result_text.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")


        # Generate Key and Keyword Buttons
        self.generate_message_button = tk.Button(self.root, text="Generate Message", bg="#333333", fg="#00FF00", font=("Courier", 12, "bold"), command=self.generate_message)
        self.generate_message_button.grid(row=8, column=0, padx=10, pady=10)
        self.generate_message_button.bind('<Button-1>', lambda event: self.message_text.focus())
        self.generate_message_button.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        self.generate_keyword_button = tk.Button(self.root, text="Generate Keyword", bg="#333333", fg="#00FF00", font=("Courier", 10), command=self.generate_keyword)
        self.generate_keyword_button.grid(row=8, column=1, padx=10, pady=10)
        self.generate_keyword_button.bind('<Button-1>', lambda event: self.keyword_entry.focus())
        self.generate_keyword_button.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        # Buttons
        self.encrypt_button = tk.Button(self.root, text="Encrypt", command=self.encrypt_message, bg="#333333", fg="#00FF00", font=("Courier", 10))
        self.encrypt_button.grid(row=8, column=2, padx=10, pady=10, sticky="we")
        self.encrypt_button.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        self.decrypt_button = tk.Button(self.root, text="Decrypt", command=self.decrypt_message, bg="#333333", fg="#00FF00", font=("Courier", 10))
        self.decrypt_button.grid(row=8, column=3, padx=10, pady=10, sticky="we")
        self.decrypt_button.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        self.clear_button = tk.Button(self.root, text="Clear", command=self.clear_fields, bg="#333333", fg="#00FF00", font=("Courier", 10))
        self.clear_button.grid(row=8, column=4, padx=10, pady=10, sticky="we")
        self.clear_button.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        # Add a button to save the result to a text file
        self.save_result_button = tk.Button(self.root, text="Save Result", command=self.save_result, bg="#333333", fg="#00FF00", font=("Courier", 10))
        self.save_result_button.grid(row=9, column=1, columnspan=3, padx=10, pady=10, sticky="we")
        self.save_result_button.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

        # Add a button to copy the result to the clipboard
        self.copy_result_button = tk.Button(self.root, text="Copy Result", command=self.copy_result, bg="#333333", fg="#00FF00", font=("Courier", 10))
        self.copy_result_button.grid(row=9, column=0, columnspan=3, padx=10, pady=10, sticky="we")
        self.copy_result_button.config(highlightbackground="#0F0F0F", highlightcolor="#0F0F0F")

    def validate_text(self, text):
        return len(text) <= 15

    def generate_message(self):
        length = RECOMMENDED_KEYWORD_LENGTH
        generated_message = generate_random_key(length)
        self.message_text.delete(0, tk.END)
        self.message_text.insert(0, generated_message)

    def generate_keyword(self):
        length = RECOMMENDED_KEYWORD_LENGTH
        generated_keyword = generate_random_keyword(length)
        self.keyword_entry.delete(0, tk.END)
        self.keyword_entry.insert(0, generated_keyword)

    def encrypt_message(self):
        message = self.message_text.get()[:RECOMMENDED_KEYWORD_LENGTH]
        keyword = self.keyword_entry.get()[:RECOMMENDED_KEYWORD_LENGTH]
        if not message or not keyword:
            messagebox.showerror("Error", "Please enter both message and keyword.")
            return
        result = vigenere_cipher(message, keyword, "Encrypt")
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, result)
        self.result_text.config(state=tk.DISABLED)

    def decrypt_message(self):
        message = self.message_text.get()[:RECOMMENDED_KEYWORD_LENGTH]
        keyword = self.keyword_entry.get()[:RECOMMENDED_KEYWORD_LENGTH]
        if not message or not keyword:
            messagebox.showerror("Error", "Please enter both message and keyword.")
            return
        result = vigenere_cipher(message, keyword, "Decrypt")
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, result)
        self.result_text.config(state=tk.DISABLED)

    def clear_fields(self):
        self.message_text.delete(0, tk.END)
        self.keyword_entry.delete(0, tk.END)
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        self.result_text.config(state=tk.DISABLED)

    def save_result(self):
        result_text = self.result_text.get("1.0", tk.END).strip()
        if not result_text:
            messagebox.showerror("Error", "No result to save.")
            return

        try:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, "w") as file:
                    file.write(result_text)
                messagebox.showinfo("Saved", f"Result saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save result: {e}")

    def copy_result(self):
        result_text = self.result_text.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(result_text)
        self.root.update()  # Force update to clipboard
        messagebox.showinfo("Copied", "Result copied to clipboard!")


if __name__ == "__main__":
    root = tk.Tk()
    app = VigenereCipherApp(root)
    root.mainloop()








