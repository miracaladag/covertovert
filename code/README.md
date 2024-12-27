 # README for Protocol Field Manipulation using the Mode Field in NTP

 ## Project Overview

 This project implements a **covert channel** using the **Mode field in the Network Time Protocol (NTP)**.
 A covert channel transmits data stealthily by exploiting protocol fields not typically monitored or used
 for communication. In this implementation, we manipulate the 3-bit Mode field in NTP packets to encode
 and decode binary messages between a sender and receiver.

 The project achieves a covert channel capacity of **9.33 bps**, demonstrating its effectiveness under test conditions.

 ## Key Features
 - **Message Encoding and Decoding**:
   - The sender encodes a binary message into the Mode field of NTP packets.
   - The receiver extracts and reconstructs the binary message by reading the Mode field.
 - **Stop Signal**:
   - Messages include a breaker (encoded as `7`) to indicate the end of communication.
 - **Configurable Parameters**:
   - Sender and receiver settings can be dynamically updated in the `config.json` file.
 - **Capacity Measurement**:
   - Measures covert channel capacity in bits per second (bps) using a 128-bit message (16 characters).
 - **Verification**:
   - Logs are generated to compare the sent and received messages for accuracy.

 ## Requirements
 - **Python Version**: 3.10
 - **Dependencies**:
   - `scapy`: For packet crafting and sniffing.
   - `struct`: For low-level manipulation of protocol fields.

 ## Parameter Limitations
 - **No Timeout or Delay**:
   - The code sends and receives packets as fast as possible, with no enforced delays or timeouts between packets.
 - **Message Length**:
   - There is no upper limit for message length. During capacity measurement, the binary message is fixed at 128 bits (16 characters).
 - **Packet Loss**:
   - Packet loss is not handled. The implementation assumes reliable delivery of packets between sender and receiver.

 ## Encoding and Decoding

 ### Encoding:
 1. Each bit of the binary message is encoded into the **Mode field** of NTP packets:
    - `Mode = 0`: Represents binary `0`.
    - `Mode = 1`: Represents binary `1`.
    - `Mode = 7`: Represents the breaker, denoting the end of the message (encoded from the `.` character).
 2. The crafted NTP packet is constructed using the following logic:
    - The Mode field occupies the last 3 bits of the first byte of the NTP packet.
    - The rest of the packet is padded with zeroes to maintain the correct structure.

 ### Decoding:
 1. The receiver listens for incoming NTP packets on a specified port and extracts the Mode field:
    - The Mode field is decoded by extracting the last 3 bits of the first byte from the packet payload.
 2. The binary message is reconstructed by appending the values (`0`, `1`) decoded from the Mode field.
 3. The receiver stops decoding when the breaker value (`7`) is detected.
 4. The resulting binary message is converted into text by mapping every 8 bits back into their corresponding ASCII characters.

 ## Configuration
 Modify the `config.json` file to update the sender and receiver parameters:
 ```json
 {
   "covert_channel_code": "CSC-PSV-NTP-MODE",
   "send": {
     "parameters": {
       "parameter1": "172.18.0.3",
       "parameter2": 123,
       "log_file_name": "Sender.log"
     }
   },
   "receive": {
     "parameters": {
       "parameter1": "p1",
       "parameter2": 123,
       "parameter3": "p3",
       "log_file_name": "Receiver.log"
     }
   }
 }
 ```

 ## Instructions

 ### Running the Covert Channel
 1. **Set Up**:
    - Ensure the testing environment is configured with the `config.json` file.
    - Start the sender and receiver on separate containers or processes.

 2. **Run the Sender**:
    ```bash
    make send
    ```
    - The sender will encode a randomly generated binary message and send it via NTP packets.

 3. **Run the Receiver**:
    ```bash
    make receive
    ```
    - The receiver will listen for NTP packets, extract the binary message from the Mode field, and log the result.

 4. **Verify the Logs**:
    - Compare `Sender.log` and `Receiver.log` to confirm message integrity.

 ### Measuring Covert Channel Capacity
 Use the `measure_capacity` function to calculate the covert channel capacity:
 - Send a 128-bit message and measure the time taken.
 - Compute the capacity using:
   \[
   \text{Capacity (bps)} = \frac{\text{Message Length (bits)}}{\text{Time Taken (seconds)}}
   \]

 **Observed Capacity**:
 - **9.33 bps** when tested in a local environment with `172.18.0.3` as the destination.

 ## Results
 - **Message Integrity**: The sent and received messages matched exactly in all tests.
 - **Capacity**: Achieved a covert channel capacity of 9.33 bps.

 ## Limitations
 1. **No Timeout or Delay**:
    - The implementation does not introduce any delays between packet transmissions.


 ## Contributors
 - **Miraç Aladağ, Selim Tarık Arı**
