import requests
import json
import time
from web3 import Web3
from colorama import init, Fore, Style
from fake_useragent import UserAgent
from datetime import datetime, timezone
from eth_account.messages import encode_defunct
from eth_account import Account

# Inisialisasi colorama
init(autoreset=True)

# Fungsi helper untuk output berwarna
def format_output(symbol, text, color):
    return f"{color}[{symbol}]{Style.RESET_ALL} {text}"

def print_process(text):
    print(format_output("+", text, Fore.YELLOW))

def print_success(text):
    print(format_output("✓", text, Fore.GREEN))

def print_error(text):
    print(format_output("×", text, Fore.RED))

def print_info(text):
    print(format_output("i", text, Fore.BLUE))

def print_detail(text):
    print(format_output("•", text, Fore.MAGENTA))

def print_warning(text):
    print(format_output("!", text, Fore.CYAN))

def print_input(text):
    return input(format_output("?", text, Fore.YELLOW))

def authenticate_with_siwe():
    """Fungsi untuk autentikasi SIWE"""
    
    # Membuat user-agent random
    ua = UserAgent()
    random_user_agent = ua.random
    
    # Membaca private key dari file key.txt
    try:
        with open('key.txt', 'r') as file:
            private_key = file.read().strip()
            if not private_key.startswith('0x'):
                private_key = '0x' + private_key
    except FileNotFoundError:
        print_error("File key.txt tidak ditemukan.")
        return
    
    # Membaca address dari file address.txt
    try:
        with open('address.txt', 'r') as file:
            address = file.read().strip()
    except FileNotFoundError:
        print_error("File address.txt tidak ditemukan.")
        return
    
    # Membaca privy-app-id dan privy-ca-id dari file privy.txt
    try:
        with open('privy.txt', 'r') as file:
            privy_data = file.read().strip()
            parts = privy_data.split('|')
            if len(parts) != 2:
                print_error("Format file privy.txt tidak sesuai. Format yang benar: 'privy-app-id | privy-ca-id'")
                return
            privy_app_id = parts[0].strip()
            privy_ca_id = parts[1].strip()
    except FileNotFoundError:
        print_error("File privy.txt tidak ditemukan.")
        return
    
    print_success(f"Menggunakan User-Agent: {random_user_agent}")
    
    # LANGKAH 1: Mendapatkan nonce baru dari endpoint init
    init_url = "https://auth.privy.io/api/v1/siwe/init"
    
    # Payload untuk init
    init_payload = {
        "address": address
    }
    
    # Headers untuk init
    headers = {
        "authority": "auth.privy.io",
        "accept": "application/json",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": "https://clashofcoins.com",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "privy-app-id": privy_app_id,
        "privy-ca-id": privy_ca_id,
        "privy-client": "react-auth:2.6.2",
        "referer": "https://clashofcoins.com/",
        "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
        "sec-fetch-storage-access": "active",
        "user-agent": random_user_agent
    }
    
    try:
        # Mengirim POST request untuk init
        init_response = requests.post(init_url, headers=headers, json=init_payload)
        
        # Memeriksa status response
        if init_response.status_code == 200:
            print_process("Request init berhasil!")
            init_data = init_response.json()
            nonce = init_data.get('nonce')
            print_success(f"Nonce baru: {nonce}")
            
            # Menyimpan response ke file
            with open('response_siwe_init.json', 'w') as file:
                json.dump(init_data, file, indent=4)
            print_success("Response init telah disimpan")
        else:
            print_error(f"Request init gagal! Status: {init_response.status_code}")
            print_error(f"Response: {init_response.text}")
            return
    except Exception as e:
        print_error(f"Error saat init: {str(e)}")
        return
    
    # Tunggu sebentar sebelum melanjutkan ke langkah authenticate
    time.sleep(1)
    
    # LANGKAH 2: Melakukan autentikasi dengan nonce yang baru didapatkan
    auth_url = "https://auth.privy.io/api/v1/siwe/authenticate"
    
    # Mendapatkan timestamp saat ini dalam format ISO 8601
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    # Membuat pesan SIWE dengan format yang tepat
    message = f"clashofcoins.com wants you to sign in with your Ethereum account:\n{address}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://clashofcoins.com\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: {issued_at}\nResources:\n- https://privy.io"
    
    # Menandatangani pesan dengan private key
    try:
        message_to_sign = encode_defunct(text=message)
        signed_message = Account.sign_message(message_to_sign, private_key=private_key)
        signature = signed_message.signature.hex()
        
        # Pastikan signature memiliki awalan "0x"
        if not signature.startswith('0x'):
            signature = '0x' + signature
        
        print_success("Pesan berhasil ditandatangani!")
        print_success("Signature Berhasil Didapatkan")
    except Exception as e:
        print_error(f"Gagal menandatangani pesan: {str(e)}")
        return
    
    # Payload untuk authenticate
    auth_payload = {
        "chainId": "eip155:1",
        "connectorType": "injected",
        "message": message,
        "mode": "login-or-sign-up",
        "signature": signature,
        "walletClientType": "bitget_wallet"
    }
    
    print_success(f"Nonce yang digunakan: {nonce}")
    print_process("Pesan SIWE yang dibuat untuk Autentikasi awal")
    
    try:
        # Mengirim POST request untuk authenticate
        auth_response = requests.post(auth_url, headers=headers, json=auth_payload)
        
        # Memeriksa status response
        if auth_response.status_code == 200:
            print_success("Request authenticate berhasil!")
            
            # Menyimpan response ke file
            with open('response_siwe_authenticate.json', 'w') as file:
                json.dump(auth_response.json(), file, indent=4)
            print_success("Response telah disimpan")
            
            # Mengembalikan token dan user agent untuk digunakan nanti
            return auth_response.json().get('token'), random_user_agent
        else:
            print_error(f"Request authenticate gagal! Status: {auth_response.status_code}")
            print_error(f"Response: {auth_response.text}")
            return None, None
    except Exception as e:
        print_error(f"Error saat authenticate: {str(e)}")
        return None, None
    
def get_user_points(token, user_agent):
    """Fungsi untuk mendapatkan data points user"""
    
    # URL API points
    points_url = "https://api.clashofcoins.co/api/user/points"
    
    # Headers untuk request
    headers = {
        "authority": "api.clashofcoins.co",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
        "authorization": f"Bearer {token}",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": "https://clashofcoins.com",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": "https://clashofcoins.com/",
        "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
        "user-agent": user_agent
    }
    
    try:
        # Mengirim GET request untuk mendapatkan points
        points_response = requests.get(points_url, headers=headers)
        
        # Memeriksa status response
        if points_response.status_code == 200:
            points_data = points_response.json()
            print_success(f"Request points berhasil! Data Points: {points_data}")
            
            # Menyimpan response ke file
            with open('response_user_points.json', 'w') as file:
                json.dump(points_data, file, indent=4)
            print_success("Response points telah disimpan")
            
            return points_data
        else:
            print_error(f"Request points gagal! Status: {points_response.status_code}")
            if points_response.text:
                print_error(f"Response error: {points_response.text}")
            return None
            
    except Exception as e:
        print_error(f"Error saat mengambil points: {str(e)}")
        return None
    
def claim_gamedrops(token, user_agent):
    """Fungsi untuk mendapatkan signature claim gamedrops"""
    
    def options_request():
        """Mengirim OPTIONS request"""
        url = "https://api.clashofcoins.co/api/gamedrops/claim"
        headers = {
            "authority": "api.clashofcoins.co",
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "access-control-request-headers": "authorization,content-type",
            "access-control-request-method": "PUT",
            "origin": "https://clashofcoins.com",
            "referer": "https://clashofcoins.com/",
            "user-agent": user_agent
        }
        
        response = requests.options(url, headers=headers)
        return response.status_code // 100 == 2

    def put_request():
        """Mengirim PUT request untuk mendapatkan signature"""
        url = "https://api.clashofcoins.co/api/gamedrops/claim"
        headers = {
            "authority": "api.clashofcoins.co",
            "accept": "application/json",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9",
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "origin": "https://clashofcoins.com",
            "referer": "https://clashofcoins.com/",
            "user-agent": user_agent
        }
        
        try:
            response = requests.put(url, headers=headers, json={})
            return response.status_code, response.json()
        except Exception as e:
            return 500, str(e)

    # Eksekusi untuk mendapatkan signature
    if options_request():
        print_process("Mempersiapkan request untuk mendapatkan signature claim...")
        status_code, response_data = put_request()
        
        if status_code == 200 and isinstance(response_data, dict):
            print_success("Berhasil mendapatkan data untuk claim!")
            print_detail("\nDetail Reward:")
            print_detail(f"    ├─ Points: {response_data.get('points', 0)}")
            print_detail(f"    └─ Coins : {response_data.get('coins', 0)}")
            
            signature = response_data.get('signature', 'None')
            print_success("\nSignature untuk proses claim selanjutnya:")
            print("=" * 80)
            print(signature)
            print("=" * 80)
            
            # Simpan hasil ke file
            with open('response_claim.json', 'w') as file:
                json.dump(response_data, file, indent=4)
            print_success("Data signature telah disimpan")
            
            return response_data
        else:
            print_error(f"Gagal mendapatkan signature! Status: {status_code}")
            print_error(f"Response error: {response_data}")
            return None
    else:
        print_error("Gagal melakukan persiapan request signature")
        return None

def estimate_gas_base_mainnet(address, signature, user_agent):
    """Fungsi untuk melakukan estimasi gas di Base Mainnet"""
    
    # Membuat data untuk request
    data = f"0xb7d86ff200000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000{len(signature[2:])//2:02x}{signature[2:]}"
    
    # Payload untuk request
    payload = {
        "id": 0,
        "jsonrpc": "2.0",
        "method": "eth_estimateGas",
        "params": [{
            "from": address,
            "to": "0x0fbBBd928EA4eDDd2EAfF51D4D412a3b65452F40",
            "data": data
        }]
    }
    
    # Headers untuk request
    headers = {
        "authority": "mainnet.base.org",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": "https://clashofcoins.com",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": "https://clashofcoins.com/",
        "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
        "user-agent": user_agent
    }
    
    try:
        print_process("Memulai proses estimasi gas di Base Mainnet...")
        print_detail(f"Menggunakan address: {address}")
        
        print_process("Mengirim request estimasi gas...")
        print_detail("Detail Request:")
        print_detail(f"    ├─ From Address: {address}")
        print_detail(f"    ├─ To Contract : 0x0fbBBd928EA4eDDd2EAfF51D4D412a3b65452F40")
        print_detail(f"    └─ Data        : {data[:100]}...")
        
        # Mengirim POST request
        response = requests.post(
            "https://mainnet.base.org/",
            headers=headers,
            json=payload
        )
        
        # Memeriksa status response
        if response.status_code == 200:
            print_success("Estimasi gas berhasil!")
            response_data = response.json()
            estimated_gas = response_data.get('result', 'Not available')
            print_detail(f"Estimated Gas: {estimated_gas}")
            
            # Simpan response ke file
            with open('response_estimate_gas.json', 'w') as file:
                json.dump(response_data, file, indent=4)
            print_success("Response telah disimpan")
            
            print_success("Proses estimasi gas selesai!")
            print_detail(f"Gas Estimation Result: {estimated_gas}")
            
            return estimated_gas
        else:
            print_error(f"Estimasi gas gagal! Status: {response.status_code}")
            print_error(f"Response error: {response.text}")
            return None
            
    except Exception as e:
        print_error(f"Error saat estimasi gas: {str(e)}")
        return None

def get_gas_price_base_mainnet(user_agent):
    """Fungsi untuk mendapatkan current gas price dari Base Mainnet"""
    
    # Payload untuk request gas price
    payload = {
        "id": 1,
        "jsonrpc": "2.0",
        "method": "eth_gasPrice"
    }
    
    # Headers untuk request
    headers = {
        "authority": "mainnet.base.org",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": "https://clashofcoins.com",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": "https://clashofcoins.com/",
        "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
        "user-agent": user_agent
    }
    
    try:
        print_process("Memulai proses mendapatkan gas price...")
        
        # Mengirim POST request
        response = requests.post(
            "https://mainnet.base.org/",
            headers=headers,
            json=payload
        )
        
        # Memeriksa status response
        if response.status_code == 200:
            print_success("Request gas price berhasil!")
            response_data = response.json()
            gas_price = response_data.get('result', 'Not available')
            print_detail(f"Current Gas Price: {gas_price}")
            
            # Simpan response ke file
            with open('response_gas_price.json', 'w') as file:
                json.dump(response_data, file, indent=4)
            print_success("Response telah disimpan")
            
            return gas_price
        else:
            print_error(f"Request gas price gagal! Status: {response.status_code}")
            print_error(f"Response error: {response.text}")
            return None
            
    except Exception as e:
        print_error(f"Error saat mendapatkan gas price: {str(e)}")
        return None

def send_transaction_base_mainnet(address, signature, gas_estimate, gas_price, user_agent, private_key):
    """Fungsi untuk mengirim transaksi ke Base Mainnet"""
    
    try:
        print_process("Mempersiapkan raw transaction...")
        
        # Inisialisasi Web3 dengan provider Base Mainnet
        w3 = Web3(Web3.HTTPProvider('https://mainnet.base.org'))
        
        print_info(f"Connected to Base Mainnet: {w3.is_connected()}")
        
        # Get nonce menggunakan RPC call langsung
        payload_nonce = {
            "jsonrpc": "2.0",
            "method": "eth_getTransactionCount",
            "params": [address, "latest"],
            "id": 1
        }
        
        headers = {
            "authority": "mainnet.base.org",
            "accept": "*/*",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "content-type": "application/json",
            "origin": "https://clashofcoins.com",
            "pragma": "no-cache",
            "priority": "u=1, i",
            "referer": "https://clashofcoins.com/",
            "sec-ch-ua": '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "user-agent": user_agent
        }
        
        # Get nonce
        nonce_response = requests.post(
            "https://mainnet.base.org/",
            headers=headers,
            json=payload_nonce
        )
        
        if nonce_response.status_code != 200:
            raise Exception(f"Failed to get nonce: {nonce_response.text}")
            
        nonce = int(nonce_response.json()['result'], 16)
        print_info(f"Current nonce: {nonce}")
        
        # Membuat data untuk transaksi
        data = f"0xb7d86ff200000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000bb8000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000{len(signature[2:])//2:02x}{signature[2:]}"
        
        # Perhitungan fee yang lebih rendah
        base_fee = int(gas_price, 16)
        priority_fee = base_fee // 8  # Menurunkan priority fee menjadi 1/8 dari base fee
        max_fee = base_fee + priority_fee  # Max fee = base fee + priority fee
        
        # Membuat raw transaction dengan fee yang lebih rendah
        transaction = {
            'nonce': nonce,
            'maxFeePerGas': max_fee,  # Fee yang lebih rendah
            'maxPriorityFeePerGas': priority_fee,  # Priority fee yang lebih rendah
            'gas': int(gas_estimate, 16),
            'from': address,
            'to': '0x0fbBBd928EA4eDDd2EAfF51D4D412a3b65452F40',
            'value': 0,
            'data': data,
            'chainId': 8453,
            'type': 2  # EIP-1559 transaction type
        }
        
        print_detail("Detail Raw Transaction:")
        print_detail(f"    ├─ From Address : {transaction['from']}")
        print_detail(f"    ├─ To Contract : {transaction['to']}")
        print_detail(f"    ├─ Gas Limit   : {hex(transaction['gas'])}")
        print_detail(f"    ├─ Max Fee     : {hex(transaction['maxFeePerGas'])}")
        print_detail(f"    ├─ Priority Fee: {hex(transaction['maxPriorityFeePerGas'])}")
        print_detail(f"    ├─ Nonce       : {hex(transaction['nonce'])}")
        print_detail(f"    ├─ Chain ID    : {hex(transaction['chainId'])}")
        print_detail(f"    └─ Type        : {hex(transaction['type'])}")
        
        # Sign the transaction
        print_process("Menandatangani transaksi...")
        
        # Convert private key to bytes if it's a string
        if isinstance(private_key, str):
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            private_key = bytes.fromhex(private_key)
        
        # Create account from private key
        account = w3.eth.account.from_key(private_key)
        
        # Sign transaction
        signed = account.sign_transaction(transaction)
        
        print_success("Transaksi berhasil ditandatangani")
        
        # Get raw transaction bytes and ensure 0x prefix
        raw_tx_hex = '0x' + signed.raw_transaction.hex()
        
        print_success("Raw Transaction Hex berhasil dibuat")
        
        # Payload untuk request
        payload = {
            "id": 2,
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx_hex]
        }
        
        print_process("Mengirim raw transaction ke network...")
        
        # Mengirim POST request
        response = requests.post(
            "https://mainnet.base.org/",
            headers=headers,
            json=payload
        )
        
        # Memeriksa status response
        if response.status_code == 200:
            response_data = response.json()
            
            if 'error' in response_data:
                print_error("Transaksi gagal!")
                print_error(f"Error: {response_data['error'].get('message', 'Unknown error')}")
                return None
            
            tx_hash = response_data.get('result')
            if tx_hash:
                print_success("Raw transaction berhasil dikirim!")
                print_success("Transaction Hash berhasil didapatkan")
                
                # Simpan response ke file
                with open('response_transaction.json', 'w') as file:
                    json.dump(response_data, file, indent=4)
                print_success("Response telah disimpan")
                
                return tx_hash
            else:
                print_error("Transaksi gagal! Tidak ada transaction hash.")
                return None
        else:
            print_error(f"Request transaksi gagal! Status: {response.status_code}")
            print_error(f"Response error: {response.text}")
            return None
            
    except Exception as e:
        print_error(f"Error saat mengirim transaksi: {str(e)}")
        print_error(f"Error detail: {str(e)}")
        return None

if __name__ == "__main__":
    try:
        print_process("\nClash of Coins Auto Claimer")
        print("=" * 50)
        print_info("Pilihan mode loop:")
        print("    1. Loop tak terbatas (infinite)")
        print("    2. Loop dengan jumlah tertentu")
        
        while True:
            try:
                mode = print_input("\nPilih mode (1/2): ").strip()
                if mode in ['1', '2']:
                    break
                print_warning("Pilihan tidak valid. Silakan pilih 1 atau 2.")
            except ValueError:
                print_error("Input tidak valid. Silakan coba lagi.")
        
        loop_count = float('inf')  # Default infinite
        if mode == '2':
            while True:
                try:
                    loop_count = int(print_input("Masukkan jumlah loop yang diinginkan: ").strip())
                    if loop_count > 0:
                        break
                    print_warning("Jumlah loop harus lebih dari 0.")
                except ValueError:
                    print_error("Input harus berupa angka bulat positif.")
        
        # Inisialisasi token dan user_agent di luar loop
        saved_token = None
        saved_user_agent = None
        current_loop = 0
        
        while current_loop < loop_count:
            try:
                current_loop += 1
                if mode == '2':
                    print_process(f"\nMemulai Loop ke-{current_loop} dari {loop_count}")
                else:
                    print_process(f"\nMemulai Loop ke-{current_loop}")
                print("=" * 50)
                
                # Coba gunakan token yang tersimpan
                if saved_token and saved_user_agent:
                    print_info("Mencoba menggunakan token sebelumnya...")
                    points_data = get_user_points(saved_token, saved_user_agent)
                    
                    if points_data is None:
                        print_warning("Token tidak valid, melakukan autentikasi ulang...")
                        result = authenticate_with_siwe()
                        if result:
                            saved_token, saved_user_agent = result
                            print_success("Autentikasi ulang berhasil!")
                        else:
                            print_error("Gagal autentikasi ulang")
                            time.sleep(60)
                            continue
                    else:
                        print_success("Token sebelumnya masih valid!")
                else:
                    print_process("Memulai proses autentikasi awal...")
                    result = authenticate_with_siwe()
                    if result:
                        saved_token, saved_user_agent = result
                        print_success("Autentikasi awal berhasil!")
                    else:
                        print_error("Gagal autentikasi awal")
                        time.sleep(60)
                        continue
                
                # Mengambil data points awal
                print_process("Mengambil data points awal...")
                points_data = get_user_points(saved_token, saved_user_agent)
                
                if points_data:
                    initial_points = int(points_data)
                    print_info(f"Points saat ini: {initial_points}")
                    
                    # Proses claim
                    print_process("Memulai proses mendapatkan signature claim...")
                    claim_result = claim_gamedrops(saved_token, saved_user_agent)
                    
                    if claim_result:
                        print_success("Berhasil mendapatkan signature!")
                        
                        try:
                            # Membaca address dan private key
                            with open('address.txt', 'r') as file:
                                address = file.read().strip()
                            with open('key.txt', 'r') as file:
                                private_key = file.read().strip()
                                if not private_key.startswith('0x'):
                                    private_key = '0x' + private_key
                            
                            # Melakukan estimasi gas
                            signature = claim_result.get('signature')
                            gas_estimate = estimate_gas_base_mainnet(address, signature, saved_user_agent)
                            
                            # Mendapatkan current gas price
                            if gas_estimate:
                                gas_price = get_gas_price_base_mainnet(saved_user_agent)
                                if gas_price:
                                    print_info(f"Estimasi Gas: {gas_estimate}")
                                    print_info(f"Current Gas Price: {gas_price}")
                                    
                                    # Mengirim transaksi
                                    tx_hash = send_transaction_base_mainnet(
                                        address,
                                        signature,
                                        gas_estimate,
                                        gas_price,
                                        saved_user_agent,
                                        private_key
                                    )
                                    
                                    if tx_hash:
                                        print_success("Transaksi claim berhasil dikirim!")
                                        print_success("Transaction Hash tersimpan di 'response_transaction.json'")
                                        
                                        # Tunggu sebentar untuk memastikan transaksi diproses
                                        print_process("Menunggu transaksi diproses...")
                                        time.sleep(10)
                                        
                                        print_process("Mengecek points final...")
                                        updated_points = get_user_points(saved_token, saved_user_agent)
                                        
                                        if updated_points:
                                            final_points = int(updated_points)
                                            print_info(f"Points akhir: {final_points}")
                                            
                                            # Hitung perubahan points
                                            points_change = final_points - initial_points
                                            if points_change > 0:
                                                print_success(f"Points bertambah: +{points_change}")
                                            elif points_change < 0:
                                                print_warning(f"Points berkurang: {points_change}")
                                            else:
                                                print_info("Tidak ada perubahan points")
                                            
                                            if current_loop < loop_count:
                                                print_info("Menunggu cooldown 10 menit sebelum claim berikutnya...")
                                                time.sleep(600)  # 10 menit cooldown
                                                print_success("Cooldown selesai!")
                                                
                        except FileNotFoundError as e:
                            print_error(f"File tidak ditemukan: {str(e)}")
                            break
                        except Exception as e:
                            print_error(f"Terjadi kesalahan: {str(e)}")
                            print_error(f"Error detail: {str(e)}")
                            time.sleep(60)
                    else:
                        print_error("Gagal mendapatkan signature untuk claim.")
                        print_info("Menunggu 1 menit sebelum mencoba lagi...")
                        time.sleep(60)
                else:
                    print_error("Gagal mendapatkan data points pengguna.")
                    saved_token = None  # Reset token karena kemungkinan expired
                    time.sleep(60)
                    
            except KeyboardInterrupt:
                print_warning("\n\nProgram dihentikan oleh user.")
                break
            except Exception as e:
                print_error(f"Terjadi kesalahan: {str(e)}")
                print_error(f"Error detail: {str(e)}")
                time.sleep(60)
        
        if current_loop >= loop_count:
            print_success("\nProgram selesai! Jumlah loop tercapai.")
            
    except KeyboardInterrupt:
        print_warning("\n\nProgram dihentikan oleh user.")
    except Exception as e:
        print_error(f"\nTerjadi kesalahan dalam program: {str(e)}")
        print_error(f"Error detail: {str(e)}")
    finally:
        print_process("\nProgram selesai.")
        print("=" * 50)
