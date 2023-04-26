/**
 * Author: Samson Zhang
 */

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;

public class BlockchainServer {
    static HashMap<String, BlockChain> Blockchains = new HashMap<>();
    private static Socket clientSocket = null;
    private static ServerSocket listenSocket = null;
    private static Scanner in;
    private PrintWriter out;
    private static BigInteger e, n;

    public static void main(String[] args) throws Exception {
        BlockchainServer server = new BlockchainServer();
        // Set up the server and listen for connection
        server.setup();
        server.listen();
        System.out.println("We have a visitor");

        long startTime, endTime;
        String response, outMsg = null;
        // continuously checking for incoming messages
        while (true) {
            if (in.hasNextLine()) {
                System.out.println();
                Gson gson = new Gson();
                String incoming = in.nextLine();
                RequestMessage incomingMsg = gson.fromJson(incoming, RequestMessage.class);

                // Verify the message with match and verify checks
                if (server.duoCheck(incomingMsg)) {
                    String clientID = incomingMsg.getClientID();
                    //if new user is vising, create a new blockchain and add to the blockchain map
                    if (Blockchains.get(clientID) == null) {
                        BlockChain newbc = newBlockChain();
                        Blockchains.put(clientID, newbc);
                    }
                    ResponseMessage responsemessage = new ResponseMessage();
                    BlockChain clientBC = Blockchains.get(clientID);

                    int choice = incomingMsg.getOperation();
                    responsemessage.setSelection(choice);
                    switch (choice) {
                        case 0:
                            //View basic blockchain status
                            responsemessage.setSize(clientBC.getChainSize());
                            responsemessage.setTotalHashes(clientBC.getTotalExpectedHashes());
                            responsemessage.setTotalDiff(clientBC.getTotalDifficulty());
                            responsemessage.setChainHash(clientBC.getChainHash());
                            responsemessage.setRecentNonce(clientBC.getLatestBlock().getNonce());
                            responsemessage.setDiff(clientBC.getLatestBlock().getDifficulty());
                            responsemessage.setHps(clientBC.getHashesPerSecond());
                            outMsg = gson.toJson(responsemessage);
                            System.out.println("Response : " + outMsg);
                            break;
                        case 1:
                            // Add a transaction to the blockchain
                            System.out.println("Adding a block");
                            int index = clientBC.getLatestBlock().getIndex() + 1;
                            startTime = System.currentTimeMillis();
                            clientBC.addBlock(new Block(index, new Timestamp(System.currentTimeMillis()), incomingMsg.getData(), incomingMsg.getDifficulty()));
                            endTime = System.currentTimeMillis();
                            long processTime = endTime - startTime;
                            response = String.format("Total execution time to add this block was %d milliseconds", processTime);
                            responsemessage.setResponse(response);
                            System.out.println("Setting response to " + response);
                            outMsg = outMsg(responsemessage);
                            System.out.println("..." + outMsg);
                            break;
                        case 2:
                            // Verify the blockchain
                            System.out.println("Verifying entire chain");
                            startTime = System.currentTimeMillis();
                            String bcValidity = clientBC.isChainValid();
                            endTime = System.currentTimeMillis();
                            response = String.format("Chain verification: %s \nTotal execution time to verify the chain was %d milliseconds", bcValidity, endTime - startTime);
                            System.out.println(response);
                            responsemessage.setResponse(response);
                            System.out.println("Setting response to " + response);
                            outMsg = outMsg(responsemessage);
                            break;
                        case 3:
                            // View the blockchain
                            System.out.println("View the Blockchain");
                            responsemessage.setResponse(clientBC.toString());
                            System.out.println("Setting response to " + clientBC.toString());
                            outMsg = outMsg(responsemessage);
                            break;
                        case 4:
                            // Corrupt the chain
                            System.out.println("corrupt the Blockchain");
                            clientBC.getBlock(incomingMsg.getDifficulty()).setData(incomingMsg.getData());
                            response = String.format("Block %d now holds %s", incomingMsg.getDifficulty(), incomingMsg.getData());
                            System.out.println(response);
                            responsemessage.setResponse(response);
                            System.out.println("Setting response to " + response);
                            outMsg = outMsg(responsemessage);
                            break;
                        case 5:
                            // Hide the corruption by repairing the chain.
                            System.out.println("Repairing the entire chain");
                            startTime = System.currentTimeMillis();
                            clientBC.repairChain();
                            endTime = System.currentTimeMillis();
                            response = String.format("Total execution time required to repair the chain was %d milliseconds", endTime - startTime);
                            responsemessage.setResponse(response);
                            System.out.println("Setting response to " + response);
                            outMsg = outMsg(responsemessage);
                            break;
                        case 6:
                            System.out.println("Client Quit.");
                            System.exit(0);
                    }
                    // Send the response back to the client
                    server.out.println(outMsg);
                    server.out.flush();
                } else {
                    // If the message is not verified, return an error message
                    System.out.println("Error in request.");
                }
            } else {
                // If there is no message to read, continue listening for connections
                server.listen();
                System.out.println("We have a visitor");
            }
        }
    }

    /**
     *  method to create a new blockchain with Genesis block
     * @return new Blockchain
     */
    private static BlockChain newBlockChain() {
        BlockChain blockchain = new BlockChain();
        blockchain.computeHashesPerSecond();
        Block genesis = new Block(0, blockchain.getTime(), "Genesis", 2);
        blockchain.addBlock(genesis);

        return blockchain;
    }

    /**
     *  formulate the response message to only selected properties
     */
    private static String outMsg(ResponseMessage responsemessage) {
        Gson gson = new Gson();
        JsonObject selectedObject = new JsonObject();
        selectedObject.addProperty("selection", responsemessage.getSelection());
        selectedObject.addProperty("response", responsemessage.getResponse());
        String messageToSend = gson.toJson(selectedObject);
        return messageToSend;
    }

    private void setup() {
        // Print a message indicating that the server started
        System.out.println("Blockchain server running");
        try {
            int serverPort = 7777; // the server port we are using
            // Create a new server socket
            listenSocket = new ServerSocket(serverPort);
        } catch (IOException e) {
            System.out.println("IO Exception:" + e.getMessage());
            // If quitting (typically by you sending quit signal) clean up sockets
        } finally {
            try {
                if (clientSocket != null) {
                    clientSocket.close();
                }
            } catch (IOException e) {
                // ignore exception on close
            }
        }
    }

    private void listen() {
        try {
            // If we get here, then we are now connected to a client.
            clientSocket = listenSocket.accept();
            // Set up "in" to read from the client socket
            in = new Scanner(clientSocket.getInputStream());
            // Set up "out" to write to the client socket
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verifies the visitor's ID and signature before allowing access to the server.
     *
     * @param requestMessage the request sent by the visitor containing their ID and signature
     * @return true if the ID and signature match, false otherwise
     * @throws Exception if there is an error with the signature verification
     */
    private boolean duoCheck(RequestMessage requestMessage) throws Exception {
        e = requestMessage.getE();
        n = requestMessage.getN();
        // match the ID with the public key
        boolean matched = match(requestMessage.getClientID(), requestMessage.getClientPublicKey());

        // concatenate all elements except the signature for verification
        String key = requestMessage.getClientID() + requestMessage.getClientPublicKey() +
                requestMessage.getOperation() + requestMessage.getData() + requestMessage.getDifficulty() +
                e + n;

        // verify the signature using the concatenated message
        boolean verified = verify(key, requestMessage.getSignature());

        return matched && verified;
    }

    /**
     * This method takes in a client public key and matches it with the given ID.
     * The client public key is hashed with SHA-256 and then the last 20 hash digits are
     * matched with the given ID to ensure authenticity.
     *
     * @param idToMatch       the ID to match
     * @param clientPublicKey the client public key to match with the ID
     * @return true if the client public key matches the ID, false otherwise
     */
    private boolean match(String idToMatch, String clientPublicKey) {
        byte[] hash = computeSHA256Hash(clientPublicKey);
        byte[] last20HashDigits = Arrays.copyOfRange(hash, hash.length - 20, hash.length);
        String calculatedID = bytesToHex(last20HashDigits);

        boolean matched = calculatedID.equals(idToMatch);

        return matched;
    }


    /**
     * Citation: https://github.com/CMU-Heinz-95702/Project-2-Client-Server/blob/master/README.md
     * <p>
     * Verifying proceeds as follows:
     * 1) Decrypt the encryptedHash to compute a decryptedHash
     * 2) Hash the messageToCheck using SHA-256 (be sure to handle
     * the extra byte as described in the signing method.)
     * 3) If this new hash is equal to the decryptedHash, return true else false.
     *
     * @param messageToCheck   a normal string that needs to be verified.
     * @param encryptedHashStr signiture string - possible evidence attesting to its origin.
     * @return true or false depending on whether the verification was a success
     * @throws Exception
     */
    public boolean verify(String messageToCheck, String encryptedHashStr) throws Exception {
        // Take the encrypted string and make it a big integer
        BigInteger encryptedHash = new BigInteger(encryptedHashStr);
        // Decrypt it
        BigInteger decryptedHash = encryptedHash.modPow(e, n);

        // Get the bytes from messageToCheck
        byte[] bytesOfMessageToCheck = messageToCheck.getBytes();

        // compute the digest of the message with SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] messageToCheckDigest = md.digest(bytesOfMessageToCheck);

        // add a 0 byte as the most significant byte to keep
        // the value to be signed non-negative.
        byte[] messageDigest = new byte[messageToCheckDigest.length + 1];
        messageDigest[0] = 0;   // most significant set to 0

            /* Citation: https://www.geeksforgeeks.org/system-arraycopy-in-java/
                for the System.arraycopy() function */
        System.arraycopy(messageToCheckDigest, 0, messageDigest, 1, messageToCheckDigest.length);

        // Make it a big int
        BigInteger bigIntegerToCheck = new BigInteger(messageDigest);

        // inform the client on how the two compare

        return bigIntegerToCheck.compareTo(decryptedHash) == 0;
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
}
