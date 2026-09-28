import socket
import ssl
import sys

def parse_url(url: str) -> tuple[str, str, int, str]: # returns protocol, host, port, and path
    if "://" in url:
        protocol, url = url.split("://", 1)
    else: 
        protocol = "http"
    
    if "/" in url:
        url, path = url.split("/", 1)
        path = "/" + path
    else:
        path = "/"
    
    if ":" in url:
        host, port = url.split(":", 1)
        if port.isdigit():
            port = int(port)
            if port <= 0 or port > 65535:
                print(f"Error: Invalid port number {port}. Port must be between 1 and 65535.")
                sys.exit(1)
        else: 
            print(f"Invalid port number: {port}. Using default port for {protocol}.")
            if protocol == "https":
                port = 443
            else:
                port = 80
    else:
        host = url
        if protocol == "https":
            port = 443
        else:
            port = 80

    return protocol, host, port, path

def parse_response(response: bytes) -> tuple[int, str, list[str]]: # returns status code, location, and header lines for cookie extraction
    header, _, body = response.partition(b"\r\n\r\n") # Split the response into header and body
    # print("_____ HEADER _____")
    # print(header.decode("utf-8"))
    # print("_____ BODY _____")
    # print(body.decode("utf-8")[:1000])  # Print only the first 1000 characters of the body
    header = header.decode("utf-8", errors="ignore") # Decode the header and ignore any errors
    header_lines = header.split("\r\n") # Split the header into lines
    status_line = header_lines[0] # Get the status line
    status_parts = status_line.split(" ") # Split the status line into parts
    status_code_int = 0
    if len(status_parts) > 1:
        status_code = status_parts[1] # Get the status code
        if status_code.isdigit():
            status_code_int = int(status_code) # Convert the status code to an integer  for easier comparison
        else:
            print(f"Error: Invalid status code {status_code}.")
            sys.exit(1)
        # print(f"Status code: {status_code_int}") # Print the status code

    location = ""
    for line in header_lines:
        if line.lower().startswith("location:"):
            _, location = line.split(sep=":", maxsplit=1) # Extract the location from the header
            break

    return status_code_int, location, header_lines


def extract_cookies(header_lines) -> list[tuple[str, str, str]]:  # returns a list of tuples containing the cookie name, expiration, and domain
    cookies = []
    extracted_cookies = []
    for line in header_lines:
        if line.lower().startswith("set-cookie:"):
            _, cookie = line.split(sep=":", maxsplit=1) # Extract the cookie from the header
            cookies.append(cookie.strip()) # Strip any whitespace from the cookie and add it to the list

    for cookie in cookies:
        parts = cookie.split(";") # Split the cookie into parts
        cookie_name = parts[0].split("=", 1)[0] # Split the name and value of the cookie
        expiration = ""
        domain = ""

        for part in parts[1:]:
            part = part.strip()

            if part.lower().startswith("expires="):
                expiration = part.split("=", 1)[1] # Get the expiration of the cookie by checking if the part starts with expires then splitting and taking the right side of the equals sign

            elif part.lower().startswith("domain="):
                domain = part.split("=", 1)[1] # Get the domain of the cookie by checking if the part starts with expires then splitting and taking the right side of the equals sign
        extracted_cookies.append((cookie_name, expiration, domain)) # Add the cookie's name, expiration, and domain to the list of extracted cookies
    
    return extracted_cookies

def send_request(protocol: str, host: str, port: int, path: str, cookie_list: list,
password_protected: list[bool], web_list: list[str], redirect_count: int, h2_support: list[bool]
) -> tuple[list[bool], list[list[tuple[str, str, str]]], list[bool], list[str]]:
    '''
    for the outputing tuple it gives the following: 
    http2_supported as a list of boolian expressions
    cookies as a nested list of tuples with the cookie name, expiration, and domain  
    password_protected as a list of boolean expressions indicating whether the site is password protected or not
    web_list as a list of strings representing the URLs of the web pages visited
    '''

    AF_INET = socket.AF_INET
    SOCK_STREAM = socket.SOCK_STREAM
    s = socket.socket(AF_INET, SOCK_STREAM)
    
    currently_password_protected = False

    web_list.append(f"{protocol}://{host}{path}")

    cookies = []

    if protocol == "http":
        try:
            s.connect((host, port))
        except socket.gaierror:
            print(f"Error: Unable to resolve host {host}. Please check the URL and try again.")
            sys.exit(1)
        except socket.ConnectionRefusedError:
            print(f"Error: Connection to {host}:{port} refused. The server may be down or not accepting connections.")
            sys.exit(1)
        except socket.TimeoutError:
            print(f"Error: Connection to {host}:{port} timed out. The server may be down or not responding.")
            sys.exit(1)
        except socket.error:
            print(f"Error: Socket error while connecting to {host}:{port}.")
            sys.exit(1)

        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode("utf-8")) # send the request
        response = b"" # Receive response

        h2_support.append(False)

        while True:
                    data = s.recv(4096) # receive data in chunks of 4096 bytes
                    if not data:
                        break
                    response += data

        s.close() # cloes the socket
        #print(response.decode("utf-8"))

    elif protocol == "https":
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2", "http/1.1"]) # Tell the server that we support HTTP/2 and HTTP/1.1
        
        try:
            conn = context.wrap_socket(s, server_hostname=host) # Wrap the socket with TLS (Transport Layer Security)
            conn.connect((host, port)) # Connect to the server
        except ssl.SSLError:
            print(f"Error: SSL error while connecting to {host}:{port}. The server may not support SSL/TLS.")
            sys.exit(1)
        except socket.gaierror:
            print(f"Error: Unable to resolve host {host}. Please check the URL and try again.")
            sys.exit(1)
        except socket.ConnectionRefusedError:
            print(f"Error: Connection to {host}:{port} refused. The server may be down or not accepting connections.")
            sys.exit(1)
        except socket.TimeoutError:
            print(f"Error: Connection to {host}:{port} timed out. The server may be down or not responding.")
            sys.exit(1)
        except socket.error:
            print(f"Error: Socket error while connecting to {host}:{port}.")
            sys.exit(1)

        proto = conn.selected_alpn_protocol() # Check which protocol was selected

        if proto == "h2":
        #     print("HTTP/2 is supported")
            h2_support.append(True)
        else:
        #     print("HTTP/2 is not supported")
            h2_support.append(False)

        # Send the HTTP/1.1 request



        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        conn.sendall(request.encode("utf-8"))
        response = b""    # Receive response

        while True:
            data = conn.recv(4096) # receive data in chunks of 4096 bytes
            if not data:
                break
            response += data
        conn.close() # Close connection
        #print(response.decode("utf-8"))
    else: 
        print(f"Unsupported protocol: {protocol}. Only 'http' and 'https' are supported.")
        sys.exit(1)   

    status_code_int, location, header_lines = parse_response(response) # Parse the response and print the status code and location if applicable
    
    cookies = extract_cookies(header_lines) # Extract cookies from the response headers
    # print("_____ COOKIES _____")
    # print(cookies) # Print the extracted cookies
    cookie_list.append(cookies) # Add the extracted cookies to the cookie list

    if status_code_int == 500:
        print("Error: Server error (500). The server encountered an internal error and was unable to complete your request.")
        sys.exit(1)
    
    if status_code_int == 404:
        print("Error: Not Found (404). The requested resource could not be found on the server.")
        sys.exit(1)

    if status_code_int == 503:
        print("Error: Service unavailable (503). The requested service is unavailable")
        sys.exit(1)

    if status_code_int == 403:
        print("Error: Forbidden location (403). The requested location is forbidden")
        sys.exit(1)

    if status_code_int == 401:
        currently_password_protected = True
    else:
        for line in header_lines:
            if line.lower().startswith("www-authenticate:"):
                currently_password_protected = True # If the header contains "www-authenticate", set password_protected to True
                break
    
    password_protected.append(currently_password_protected) # Add the password protection status to the list

    if status_code_int == 301 or status_code_int == 302:
            # print("Redirect Location: here")
            # print(location.strip()) # Print the location
            new_url = location.strip() # Strip any whitespace from the location

            if new_url == "":
                print("Redirect location is empty. Cannot follow redirect.")
                sys.exit(1)

            protocol, host, port, path = parse_url(new_url)

            if protocol not in ["http", "https"]:
                print(f"Unsupported protocol in redirect: {protocol}. Only 'http' and 'https' are supported.")
                sys.exit(1)
            if host == "":
                print("Error: Host is empty in redirect.")
                sys.exit(1)

            #print(protocol, host, port, path)
            return send_request(protocol, host, port, path, cookie_list, password_protected, web_list, redirect_count + 1, h2_support) # If the status code is 301 or 302, send the request again with the new location
    
   
    return h2_support, cookie_list, password_protected, web_list
    
def create_output_file(http2_supported: bool, cookies:list[list[tuple[str, str, str]]], password_protected:list[bool], web_list:list[str]) -> None:
    with open("output.txt", "w") as file:
        for i in range(len(web_list)):
            if i > 0:
                file.write(f'Redirect Website Numer: {i}\n')
            file.write(f'Website: {web_list[i]}\n')
            file.write(f'Website supports http2: {http2_supported[i]} \n')
            file.write(f'Is password protected: {password_protected[i]}\n')
            for j in range(len(cookies[i])):
                cookie = cookies[i][j]
                cookie_name = 'None'
                cookie_experation = 'None'
                cookie_domain = 'None'
                for k in range(len(cookie)):
                    if k == 0:
                        cookie_name = cookie[k]
                    elif k == 1:
                        if cookie[k] != '':
                            cookie_experation = cookie[k]                            
                    elif k == 2:
                        if cookie[k] != '':
                            cookie_domain = cookie[k]                              
                
                file.write(f'Cookie Index: {j}  --Cookie Name: {cookie_name}  --Cookie Experation: {cookie_experation}  --Domain: {cookie_domain}\n')
            file.write("\n")

def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python WebTester.py <URL>")
        sys.exit(1)
    
    uri = sys.argv[1]

    protocol, host, port, path = parse_url(uri)

    if protocol not in ["http", "https"]:
        print(f"Unsupported protocol: {protocol}. Only 'http' and 'https' are supported.")
        sys.exit(1)
    if host == "":
        print("Error: Host is empty. Please provide a valid URL.")
        sys.exit(1)
    
    #print(protocol, host, port, path)
    http2_supported, cookies, password_protected, web_list = send_request(protocol, host, port, path, [], [], [], 0, [])
    
    create_output_file(http2_supported, cookies, password_protected, web_list)
    
    
if __name__ == "__main__":
    main()