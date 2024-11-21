from scapy.all import sniff, TCP, Raw
import json
import threading

# 전역 변수
captured_packets = []
stream_index = 0
capture_running = False
capture_thread = None

# 패킷 분석 함수
def analyze_packet(packet):
    global stream_index
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        ip_layer = packet.payload  # IP 레이어
        data_length = len(packet[Raw]) if packet.haslayer(Raw) else 0  # 데이터 길이

        # 플래그 확인
        flags = tcp_layer.flags
        syn_flag = "SYN" if flags & 0x02 else ""
        ack_flag = "ACK" if flags & 0x10 else ""

        # GET 요청 확인
        http_get = ""
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")
            if "GET" in payload:
                http_get = "GET Request Detected"

        # 패킷 정보 출력
        print("패킷 캡쳐")  # 패킷이 캡처될 때 출력
        print(f"\n[Stream Index: {stream_index}]")
        print(f"Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        print(f"Seq: {tcp_layer.seq}, Ack: {tcp_layer.ack}")
        print(f"Len: {data_length}, Flags: {syn_flag} {ack_flag}")
        print(f"Src IP: {ip_layer.src}, Dst IP: {ip_layer.dst}")
        if http_get:
            print(f"HTTP Info: {http_get}")

        # 캡처한 패킷 저장
        captured_packets.append({
            "Stream Index": stream_index,
            "Src Port": tcp_layer.sport,
            "Dst Port": tcp_layer.dport,
            "Seq": tcp_layer.seq,
            "Ack": tcp_layer.ack,
            "Len": data_length,
            "Flags": f"{syn_flag} {ack_flag}".strip(),
            "Src IP": ip_layer.src,
            "Dst IP": ip_layer.dst,
            "HTTP Info": http_get
        })
        stream_index += 1

# 패킷 캡처 함수
def start_sniffing():
    global capture_running
    try:
        sniff(filter="tcp", prn=analyze_packet, store=0, stop_filter=lambda _: not capture_running)
    except Exception as e:
        print(f"패킷 캡처 오류: {e}")

# 캡처 시작 및 중지 토글
def toggle_capture():
    global capture_running, capture_thread
    if not capture_running:
        capture_running = True
        capture_thread = threading.Thread(target=start_sniffing, daemon=True)
        capture_thread.start()
        print("패킷 캡처를 시작합니다.")
    else:
        capture_running = False
        if capture_thread:
            capture_thread.join()  # 캡처 스레드가 안전하게 종료될 때까지 대기
        print("패킷 캡처를 중지했습니다.")

# 패킷 저장 함수
def save_packets_to_file():
    try:
        with open("captured_packets.json", "w") as file:
            json.dump(captured_packets, file, indent=4)
        print("패킷 데이터가 'captured_packets.json'에 저장되었습니다.")
    except Exception as e:
        print(f"파일 저장 오류: {e}")

# 메뉴 함수
def menu():
    global captured_packets

    while True:
        print("\n메뉴:")
        print("1: 패킷 캡처 시작/중지")
        print("2: 캡처된 패킷 보기")
        print("3: 패킷 파일 저장")
        print("0: 종료")
        choice = input("선택: ").strip()

        if choice == "1":
            toggle_capture()

        elif choice == "2":
            if captured_packets:
                print(f"\n총 {len(captured_packets)}개의 패킷이 캡처되었습니다.")
                for packet in captured_packets[:5]:  # 처음 5개만 출력
                    print(packet)
            else:
                print("캡처된 패킷이 없습니다.")

        elif choice == "3":
            save_packets_to_file()

        elif choice == "0":
            if capture_running:
                print("패킷 캡처를 중지하고 프로그램을 종료합니다.")
                capture_running = False
                if capture_thread:
                    capture_thread.join()
            print("프로그램을 종료합니다.")
            break

        else:
            print("잘못된 입력입니다. 다시 시도해주세요.")

# 프로그램 실행
if __name__ == "__main__":
    menu()
