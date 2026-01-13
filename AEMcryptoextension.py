from burp import IBurpExtender
from burp import IIntruderPayloadProcessor
from burp import IContextMenuFactory
from burp import ITab
from java.security import MessageDigest
from javax.crypto import SecretKeyFactory
from javax.crypto.spec import PBEKeySpec, SecretKeySpec, IvParameterSpec
from javax.crypto import Cipher
from javax.swing import JMenuItem, JScrollPane, JTextArea, JPanel, JButton, JSplitPane
from javax.swing import BoxLayout, BorderFactory
from java.util import ArrayList
from java.awt import Dimension, BorderLayout, FlowLayout
from java.awt.datatransfer import StringSelection, DataFlavor
from java.awt import Toolkit
import array
import binascii
import base64
import json

# ------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------
PASSPHRASE = "d6163f0659cfe4196dc03c2c29aab06f10cb0a79cdfc74a45da2d72358712e80"
SALT_STRING = "fc74a45dsalt"
IV_STRING = "c29aab06iv"
ITERATIONS = 100
KEY_SIZE_BITS = 128
# ------------------------------------------------------------------------

class BurpExtender(IBurpExtender, IIntruderPayloadProcessor, IContextMenuFactory, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("CryptoJS Encryptor/Decryptor (Menu Only)")
        
        # Register components
        callbacks.registerIntruderPayloadProcessor(self)
        callbacks.registerContextMenuFactory(self)
        
        print("[-] Extension Loaded: Context Menu Mode")
        
        # Pre-calculate Key and IV
        try:
            self.static_salt = self.get_md5_bytes(SALT_STRING)
            self.static_iv = self.get_md5_bytes(IV_STRING)
            self.static_key = self.generate_pbkdf2(PASSPHRASE, self.static_salt)
            print("[-] Static Key Generated Successfully")
        except Exception as e:
            print("[-] Error generating static key: " + str(e))
            
        # Create and register the persistent Crypto Inspector tab
        try:
            self._create_inspector_tab()
            callbacks.addSuiteTab(self)
            print("[-] Inspector Tab Added")
        except Exception as e:
            print("[-] Error creating inspector tab: " + str(e))

        return

    # --------------------------------------------------------------------
    # Intruder Payload Processor
    # --------------------------------------------------------------------
    def getProcessorName(self):
        return "CryptoJS Encryptor"

    def processPayload(self, currentPayload, originalPayload, baseValue):
        try:
            plaintext_data = self._helpers.bytesToString(currentPayload)
            encrypted_bytes = self.encrypt_aes(plaintext_data, self.static_key, self.static_iv)
            return base64.b64encode(encrypted_bytes)
        except Exception as e:
            print("Error processing payload: " + str(e))
            return currentPayload

    # --------------------------------------------------------------------
    # Context Menu Factory (The "Inspector" Replacement)
    # --------------------------------------------------------------------
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        
        # Option 1: Preview (Inspect without changing)
        menu_view = JMenuItem("CryptoJS: Preview Decryption (Inspector)", actionPerformed=lambda x: self.handle_menu_action(invocation, "preview"))
        
        # Option 2 & 3: Modify in place
        menu_enc = JMenuItem("CryptoJS: Encrypt Selection", actionPerformed=lambda x: self.handle_menu_action(invocation, "encrypt"))
        menu_dec = JMenuItem("CryptoJS: Decrypt Selection", actionPerformed=lambda x: self.handle_menu_action(invocation, "decrypt"))
        
        menu_list.add(menu_view)
        menu_list.add(menu_enc)
        menu_list.add(menu_dec)
        menu_open = JMenuItem("CryptoJS: Open Inspector", actionPerformed=lambda x: self.handle_menu_action(invocation, "inspector"))
        menu_list.add(menu_open)
        return menu_list

    def handle_menu_action(self, invocation, mode):
        messages = invocation.getSelectedMessages()
        if not messages: return
        messageInfo = messages[0]
        bounds = invocation.getSelectionBounds()
        
        # If no text selected, do nothing
        if bounds[0] == bounds[1]: return

        # Determine context (Request vs Response)
        ctx = invocation.getInvocationContext()
        is_request = True
        if ctx in [invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE, invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE, invocation.CONTEXT_PROXY_HISTORY, invocation.CONTEXT_SEARCH_RESULTS]:
            is_request = False
        
        full_bytes = messageInfo.getRequest() if is_request else messageInfo.getResponse()
        if not full_bytes: return

        selected_bytes = full_bytes[bounds[0]:bounds[1]]
        selected_text = self._helpers.bytesToString(selected_bytes)
        
        try:
            if mode == "preview":
                # Decrypt and show popup
                clean_input = selected_text.strip().replace('\n', '').replace('\r', '')
                ciphertext_bytes = base64.b64decode(clean_input)
                dec_bytes = self.decrypt_aes(ciphertext_bytes, self.static_key, self.static_iv)
                decrypted_text = self._helpers.bytesToString(dec_bytes)
                self.show_preview_popup(decrypted_text)
                # Also populate persistent inspector (if available)
                try:
                    if hasattr(self, 'inspector_panel'):
                        self.encrypted_area.setText(clean_input)
                        self.decrypted_area.setText(decrypted_text)
                except:
                    pass
                return # Do not modify message

            elif mode == "encrypt":
                enc_bytes = self.encrypt_aes(selected_text, self.static_key, self.static_iv)
                result_text = base64.b64encode(enc_bytes)
                result_bytes = self._helpers.stringToBytes(result_text)
                # Update inspector
                try:
                    if hasattr(self, 'inspector_panel'):
                        self.encrypted_area.setText(result_text)
                        self.decrypted_area.setText(selected_text)
                except:
                    pass
                
            elif mode == "decrypt":
                clean_input = selected_text.strip().replace('\n', '').replace('\r', '')
                ciphertext_bytes = base64.b64decode(clean_input)
                dec_bytes = self.decrypt_aes(ciphertext_bytes, self.static_key, self.static_iv)
                result_bytes = dec_bytes
                # Update inspector
                try:
                    if hasattr(self, 'inspector_panel'):
                        self.encrypted_area.setText(selected_text)
                        self.decrypted_area.setText(self._helpers.bytesToString(dec_bytes))
                except:
                    pass

            elif mode == "inspector":
                # Load selection into the persistent inspector tab
                self.set_inspector_contents(selected_text)
                return

            # Apply changes to the editor
            if result_bytes:
                new_message = full_bytes[:bounds[0]] + result_bytes + full_bytes[bounds[1]:]
                if is_request:
                    messageInfo.setRequest(new_message)
                else:
                    messageInfo.setResponse(new_message)

        except Exception as e:
            error_msg = "Operation failed: " + str(e)
            print("[-] " + error_msg)
            if mode == "preview":
                self.show_preview_popup(error_msg)

    def show_preview_popup(self, text):
        # Attempt to format as JSON and populate inspector instead of showing a dialog
        display_text = text
        try:
            parsed_json = json.loads(text)
            display_text = json.dumps(parsed_json, indent=4)
        except:
            pass

        # If inspector panel exists, update decrypted area with preview text
        try:
            if hasattr(self, 'inspector_panel') and self.decrypted_area is not None:
                self.decrypted_area.setText(display_text)
                return
        except:
            pass

        # Fallback: print to console
        print(display_text)

    # --------------------------------------------------------------------
    # Inspector Tab UI
    # --------------------------------------------------------------------
    def getTabCaption(self):
        return "Crypto Inspector"

    def getUiComponent(self):
        return self.inspector_panel

    def _create_inspector_tab(self):
        self.inspector_panel = JPanel()
        self.inspector_panel.setLayout(BorderLayout())

        # Toolbar
        toolbar = JPanel()
        toolbar.setLayout(FlowLayout(FlowLayout.LEFT))
        load_btn = JButton("Load Selection", actionPerformed=lambda ev: self._prompt_load_selection())
        decrypt_btn = JButton("Decrypt", actionPerformed=lambda ev: self._inspector_decrypt_action())
        encrypt_btn = JButton("Encrypt", actionPerformed=lambda ev: self._inspector_encrypt_action())
        clear_btn = JButton("Clear", actionPerformed=lambda ev: self._clear_inspector())
        toolbar.add(load_btn)
        toolbar.add(decrypt_btn)
        toolbar.add(encrypt_btn)
        toolbar.add(clear_btn)

        # Text areas
        self.encrypted_area = JTextArea()
        self.encrypted_area.setLineWrap(True)
        self.encrypted_area.setWrapStyleWord(True)
        self.decrypted_area = JTextArea()
        self.decrypted_area.setLineWrap(True)
        self.decrypted_area.setWrapStyleWord(True)

        left_scroll = JScrollPane(self.encrypted_area)
        right_scroll = JScrollPane(self.decrypted_area)
        left_scroll.setPreferredSize(Dimension(400, 400))
        right_scroll.setPreferredSize(Dimension(400, 400))

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left_scroll, right_scroll)
        split.setResizeWeight(0.5)

        self.inspector_panel.add(toolbar, BorderLayout.NORTH)
        self.inspector_panel.add(split, BorderLayout.CENTER)
        self.inspector_panel.setBorder(BorderFactory.createTitledBorder("CryptoJS Inspector"))

        self.inspector_tab_ready = True

    def _prompt_load_selection(self):
        # Load selection from clipboard (no popup)
        try:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            contents = clipboard.getContents(None)
            if contents is not None and contents.isDataFlavorSupported(DataFlavor.stringFlavor):
                s = contents.getTransferData(DataFlavor.stringFlavor)
                if s:
                    self.set_inspector_contents(s)
        except Exception as e:
            # Ignore clipboard errors
            print("Clipboard load failed: " + str(e))

    def set_inspector_contents(self, text):
        clean_input = text.strip().replace('\n', '').replace('\r', '')
        # set encrypted area to original
        self.encrypted_area.setText(clean_input)
        # attempt to decode and decrypt
        try:
            ciphertext_bytes = base64.b64decode(clean_input)
            dec_bytes = self.decrypt_aes(ciphertext_bytes, self.static_key, self.static_iv)
            decrypted_text = self._helpers.bytesToString(dec_bytes)
            self.decrypted_area.setText(decrypted_text)
        except Exception:
            # not base64 or can't decrypt; leave decrypted empty
            self.decrypted_area.setText("")

    def _inspector_decrypt_action(self):
        enc_text = self.encrypted_area.getText().strip().replace('\n','').replace('\r','')
        try:
            ciphertext_bytes = base64.b64decode(enc_text)
            dec_bytes = self.decrypt_aes(ciphertext_bytes, self.static_key, self.static_iv)
            self.decrypted_area.setText(self._helpers.bytesToString(dec_bytes))
            print("Decryption succeeded.")
        except Exception as e:
            self.decrypted_area.setText("")
            print("Decryption failed: " + str(e))

    def _inspector_encrypt_action(self):
        plain_text = self.decrypted_area.getText()
        try:
            enc_bytes = self.encrypt_aes(plain_text, self.static_key, self.static_iv)
            self.encrypted_area.setText(base64.b64encode(enc_bytes))
            print("Encryption succeeded.")
        except Exception as e:
            print("Encryption failed: " + str(e))

    def _clear_inspector(self):
        self.encrypted_area.setText("")
        self.decrypted_area.setText("")
    # --------------------------------------------------------------------
    # Cryptographic Primitives
    # --------------------------------------------------------------------
    def get_md5_bytes(self, input_string):
        md = MessageDigest.getInstance("MD5")
        md.update(input_string.encode('utf-8'))
        return md.digest()

    def generate_pbkdf2(self, passphrase, salt_bytes):
        spec = PBEKeySpec(passphrase, salt_bytes, ITERATIONS, KEY_SIZE_BITS)
        skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        return skf.generateSecret(spec).getEncoded()

    def encrypt_aes(self, plaintext, key_bytes, iv_bytes):
        spec = SecretKeySpec(key_bytes, "AES")
        iv_spec = IvParameterSpec(iv_bytes)
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, spec, iv_spec)
        return cipher.doFinal(plaintext.encode('utf-8'))

    def decrypt_aes(self, ciphertext_bytes, key_bytes, iv_bytes):
        spec = SecretKeySpec(key_bytes, "AES")
        iv_spec = IvParameterSpec(iv_bytes)
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, spec, iv_spec)
        return cipher.doFinal(ciphertext_bytes)