/**
 * Author: Samson Zhang
 */

import com.google.gson.Gson;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class BlockchainClient {
    private int serverPort = 7777;
    private static Socket clientSocket = null;
    private PrintWriter out;
    private BufferedReader in;
    private static BigInteger n, e, d;
    private static String clientPrivateKey, clientPublicKey, clientID;
    private static final String MENU = "\n0. View basic blockchain status.\n" +
            "1. Add a transaction to the blockchain.\n" +
            "2. Verify the blockchain.\n" +
            "3. View the blockchain.\n" +
            "4. Corrupt the chain.\n" +
            "5. Hide the corruption by repairing the chain.\n" +
            "6. Exit";

    public static void main(String[] args) {
        BlockchainClient client = new BlockchainClient();
        initializeClient(client);

        // create a scanner for user input
        Scanner scanner = new Scanner(System.in);
        String data = "";
        int difficulty = -1;
        while (true) {
            // menu input
            System.out.println(MENU);
            System.out.print("Enter Choice: ");
            int choice = Integer.parseInt(scanner.nextLine());
            switch (choice) {
                case 1:
                    System.out.println("Enter difficulty > 0: ");
                    difficulty = Integer.parseInt(scanner.nextLine());
                    System.out.println("Enter transaction: ");
                    data = scanner.nextLine();
                    break;
                case 2, 5:
                    break;
                case 3:
                    System.out.println("View the blockchain");
                    break;
                case 4:
                    System.out.println("Corrupt the Blockchain");
                    System.out.println("Enter block ID of block to corrupt: ");
                    difficulty = Integer.parseInt(scanner.nextLine());
                    System.out.println(String.format("Enter new data for block %d: ", difficulty));
                    data = scanner.nextLine();
                    break;
                case 6:
                    System.exit(0);
            }
            String key = clientID + clientPublicKey + choice + data + difficulty + e + n;
            String signature = client.generateSignature(key);
            RequestMessage requestMessage = new RequestMessage(clientID, clientPublicKey, choice, data, difficulty, e, n, signature);
            client.send(requestMessage);

            ResponseMessage responseMessage  = client.receive();

            // parse the response message
            switch (responseMessage.getSelection()){
                case 0:
                    System.out.println("Current size of chain: " + responseMessage.getSize());
                    System.out.println("Difficulty of most recent block: " + responseMessage.getDiff());
                    System.out.println("Total difficulty for all blocks: " + responseMessage.getTotalDiff());
                    System.out.println("Approximate hashes per second on this machine: " + responseMessage.getHps());
                    System.out.println("Expected total hashes required for the whole chain: " + responseMessage.getTotalHashes());
                    System.out.println("Nonce for most recent block: " + responseMessage.getRecentNonce());
                    System.out.println("Chain hash: " + responseMessage.getChainHash());
                    break;
                default:
                    System.out.println(responseMessage.getResponse());
                    break;
            }
        }


    }

    /**
     * initialize the blockchain client by connect to the socket port, and compute the ClientID
     * @param client
     */
    public static void initializeClient(BlockchainClient client){
        client.connect();
        System.out.println("The client is running.");
        client.computeRSAKeys();
        client.createClientID(clientPublicKey);
    }


    /*
    Citation:
    The computeRSAKeys method is part of the RSAExample Class from Project2Task 5 of this document:
    https://github.com/CMU-Heinz-95702/Project-2-Client-Server/blob/master/README.md
 */
    private void computeRSAKeys() {
        Random rnd = new Random();

        // Step 1: Generate two large random primes.
        BigInteger p = new BigInteger(400, 100, rnd);
        BigInteger q = new BigInteger(400, 100, rnd);

        // Step 2: Compute n by the equation n = p * q.
        n = p.multiply(q);

        // Step 3: Compute phi(n) = (p-1) * (q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Step 4: Select a small odd integer e that is relatively prime to phi(n).
        // By convention the prime 65537 is used as the public exponent.
        e = new BigInteger("65537");

        // Step 5: Compute d as the multiplicative inverse of e modulo phi(n).
        d = e.modInverse(phi);

        //private key (d and n)
        clientPrivateKey = d.toString() + n.toString();

        //public key (e and n)
        clientPublicKey = e.toString() + n.toString();
    }

    private void createClientID(String clientPublicKey) {
        // creaste the ClientID as the last20BytesOf(h(e+n))
        byte[] hash = computeSHA256Hash(clientPublicKey);
        byte[] last20HashDigits = Arrays.copyOfRange(hash, hash.length - 20, hash.length);

        // convert the hash value as a hexadecimal string
        clientID = bytesToHex(last20HashDigits);
        System.out.println("Client ID: " + clientID);
    }

    // Compute the SHA-256 hash of the given message
    private static byte[] computeSHA256Hash(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(message.getBytes());
            return hash;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /*
        Citation:
        This bytesToHex function was part of the project1 Exercise 1 Answer from:
        https://github.com/CMU-Heinz-95702/Lab1-InstallationAndRaft

        This function converts a byte array to a hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private String generateSignature(String message) {

        try {
            // compute the digest with SHA-256
            byte[] bytesOfMessage = message.getBytes();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bigDigest = md.digest(bytesOfMessage);

            // add a 0 byte as the most significant byte to keep
            // the value to be signed non-negative.
            /* Citation: https://www.geeksforgeeks.org/system-arraycopy-in-java/
                for the System.arraycopy() function */
            byte[] messageDigest = new byte[bigDigest.length + 1];
            messageDigest[0] = 0;   // most significant set to 0
            System.arraycopy(bigDigest, 0, messageDigest, 1, bigDigest.length);

            // From the digest, create a BigInteger
            BigInteger m = new BigInteger(messageDigest);

            // encrypt the digest with the private key
            BigInteger c = m.modPow(d, n);

            // return this as a big integer string
            return c.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    public void connect() {
        try {
            // Create a new socket to connect to the localhost on the specified port.
            clientSocket = new Socket("localhost", serverPort);
            // Create a BufferedReader to read input from the server.
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            // Create a PrintWriter to send output to the server.
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void disconnect() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public void send(RequestMessage request) {
        // Create a Gson object
        Gson gson = new Gson();
        // Serialize to JSON
        String messageToSend = gson.toJson(request);
        // Send the request to the server
        out.println(messageToSend);
        out.flush();
    }

    /**
     * This method reads a JSON string from server and convert it into a ResponseMessage Object
     * @return ResponseMessage object
     */
    public ResponseMessage receive(){
        try {
            Gson gson = new Gson();
            String data = in.readLine();
            ResponseMessage responseMessage = gson.fromJson(data, ResponseMessage.class);
            return responseMessage;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
