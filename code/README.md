 ## README for Protocol Field Manipulation using the Mode Field in NTP

 ### Project Overview

 This project implements a **covert channel** using the **Mode field in the Network Time Protocol (NTP)**.
 A covert channel transmits data stealthily by exploiting protocol fields not typically monitored or used
 for communication. In this implementation, we manipulate the 3-bit Mode field in NTP packets to encode
 and decode binary messages between a sender and receiver.

 The project achieves a covert channel capacity of **9.33 bps**, demonstrating its effectiveness under test conditions.

 ### Key Features
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

 ### Requirements
 - **Python Version**: 3.10
 - **Dependencies**:
   - `scapy`: For packet crafting and sniffing.
   - `struct`: For low-level manipulation of protocol fields.

 ### Configuration
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

 ### Instructions

 #### Running the Covert Channel
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

 #### Measuring Covert Channel Capacity
 Use the `measure_capacity` function to calculate the covert channel capacity:
 - Send a 128-bit message and measure the time taken.
 - Compute the capacity using:
   \[
   \text{Capacity (bps)} = \frac{\text{Message Length (bits)}}{\text{Time Taken (seconds)}}
   \]

 **Observed Capacity**:
 - **9.33 bps** when tested in a local environment with `172.18.0.3` as the destination.

 ### Results
 - **Message Integrity**: The sent and received messages matched exactly in all tests.
 - **Capacity**: Achieved a covert channel capacity of 9.33 bps.

 ### Limitations
 1. **Latency**:
    - Delays in the network may lower the covert channel capacity.
 2. **Packet Loss**:
    - If packets are dropped during transmission, the receiver may not reconstruct the message accurately.
 3. **Traffic Analysis**:
    - Unusual patterns in NTP traffic, such as excessive Mode field manipulation, might be detected with advanced monitoring tools.

 ### Next Steps
 - Explore additional protocol fields or other layers for covert channel implementation.
 - Improve the packet sending mechanism to enhance throughput and reduce latency.
 - Test the implementation under real-world conditions with higher traffic volumes.

 ### Contributors
 - **Your Name**: Implementation and testing
 - **[Your Team Name]**
