
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

/**
 * PENEVAL Cifrado clave pública - FASE 2
 * ----------------------------------------
 *
 * @author Rubén
 */
public class Main {

    private static File ficheroOrigen;
    private static File ficheroCifrado;
    private static File ficheroClave;
    private static String rutaFicheroOrigen;
    private static String rutaFicheroCifrado;
    private static String rutaFicheroClave;
    private static Ventana ventana;

    public static void main(String[] args) {
        //Creación y visualización de la interfaz gráfica.
        ventana = new Ventana();
        ventana.setVisible(true);
        ventana.setLocationRelativeTo(null);

        rutaFicheroOrigen = "./src/ficheros/fichero_clave_privada_origen.txt";
        rutaFicheroCifrado = "./src/ficheros/fichero_clave_codificado.txt";
        rutaFicheroClave = "./src/ficheros/fichero_clave_privada.txt";
    }

    public static void realizarProceso() {
        KeyPair parClaves = null;
        if (asignarRutaFicheroClave() && asignarRutaFicheroCodificado()) {
            //Generador de pares de claves RSA
            try {
                parClaves = generarParesClavesRSA();
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
                JOptionPane.showMessageDialog(ventana, "ERROR en la generación de la clave RSA: " + ex, "ERROR", JOptionPane.ERROR);
            }
            //Encriptación del fichero de la clave de la fase 1, mediante RSA
            try {
                encriptarFichero(parClaves, new FileInputStream(ficheroOrigen), new FileOutputStream(ficheroCifrado));
            } catch (FileNotFoundException ex) {
                JOptionPane.showMessageDialog(ventana, "ERROR en la encriptación de la clave DES: " + ex, "ERROR", JOptionPane.ERROR);
            } catch (InvalidKeyException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | IOException ex) {
                JOptionPane.showMessageDialog(ventana, "ERROR en la encriptación de la clave DES: " + ex, "ERROR", JOptionPane.ERROR);
            }
            //Guardado de la clave RSA
            try {
                almacenarClaveRSA(parClaves, new FileOutputStream(ficheroClave));
            } catch (InvalidKeySpecException | NoSuchAlgorithmException | FileNotFoundException ex) {
                JOptionPane.showMessageDialog(ventana, "ERROR en el almacenamiento de la clave RSA: " + ex, "ERROR", JOptionPane.ERROR);
            }
            ventana.setIconoCifrado(true);
            ventana.setProcesoTerminado();
            ventana.setTextoConsola("\nEL PROCESO HA FINALIZADO CORRECTAMENTE\nSe han generado 2 ficheros: 1 clave de encriptación y 1 fichero encriptado.");
        } else {
            JOptionPane.showMessageDialog(ventana, "Operación cancelada, debe indicar un directorio de destino");
        }
    }

    private static KeyPair generarParesClavesRSA() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        System.out.println("Generando par de claves");
        ventana.setTextoConsola("Generando par de claves");
        KeyPair keypair = keygen.generateKeyPair();

        return keypair;
    }

    private static void encriptarFichero(KeyPair parClaves, FileInputStream flujoLecturaOrigen, FileOutputStream flujoEscrituraCifrado) throws InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, IOException {
        System.out.println("Obteniendo objeto Cipher con cifrado RSA");
        ventana.setTextoConsola("Obteniendo objeto Cipher con cifrado RSA");
        Cipher desCipher = Cipher.getInstance("RSA");
        System.out.println("Configurando Cipher para encriptar");
        ventana.setTextoConsola("Configurando Cipher para encriptar");
        desCipher.init(Cipher.ENCRYPT_MODE, parClaves.getPrivate());
        System.out.println("Cifrando el fichero...");
        ventana.setTextoConsola("Cifrando el fichero...");
        byte[] buffer = new byte[64];
        int bytes_leidos = flujoLecturaOrigen.read(buffer);
        while (bytes_leidos != -1) {
            byte[] cbuf = desCipher.doFinal(buffer, 0, bytes_leidos);
            flujoEscrituraCifrado.write(cbuf);
            bytes_leidos = flujoLecturaOrigen.read(buffer);
        }
        flujoEscrituraCifrado.close();
    }

    private static void almacenarClaveRSA(KeyPair parClaves, FileOutputStream flujoEscrituraClave) throws InvalidKeySpecException, NoSuchAlgorithmException {
        System.out.println("Obteniendo factoría de claves con cifrado RSA");
        ventana.setTextoConsola("Obteniendo factoría de claves con cifrado RSA");
        KeyFactory keyfac = KeyFactory.getInstance("RSA");
        System.out.println("Generando keyspec");
        ventana.setTextoConsola("Generando keyspec");
        RSAPublicKeySpec publicKeySpec = keyfac.getKeySpec(parClaves.getPublic(), RSAPublicKeySpec.class);
        System.out.println("Salvando la clave en un fichero");
        ventana.setTextoConsola("Salvando la clave en un fichero");
        PrintWriter pw = new PrintWriter(flujoEscrituraClave);
        pw.println(publicKeySpec.getModulus());
        pw.println(publicKeySpec.getPublicExponent());
        pw.close();
    }

    public static void abrirFicheroOrigen() {
        JFileChooser selector = new JFileChooser(rutaFicheroOrigen);
        selector.setDialogTitle("Abrir fichero con la clave DES de la fase 1");
        selector.showOpenDialog(ventana);
        if (selector.getSelectedFile() != null) {
            ficheroOrigen = new File(selector.getSelectedFile().getPath());
            ventana.setTextoConsola("El fichero de origen que se utilizará se encuentra en:\n" + ficheroOrigen.getPath());
            ventana.setFicherosSeleccionados();
        } else {
            JOptionPane.showMessageDialog(ventana, "Debe seleccionar un fichero a encriptar");
        }
    }

    public static void abrirFicheroClave() {
        try {
            java.awt.Desktop.getDesktop().edit(ficheroClave);
        } catch (IOException ex) {
            System.out.println("ERROR en la apertura del fichero clave: " + ex);
        }
    }

    public static void abrirFicheroCodificado() {
        try {
            java.awt.Desktop.getDesktop().edit(ficheroCifrado);
        } catch (IOException ex) {
            System.out.println("ERROR en la apertura del fichero codificado: " + ex);
        }
    }

    private static boolean asignarRutaFicheroClave() {
        JFileChooser selector = new JFileChooser(rutaFicheroClave);
        selector.setDialogTitle("Guardar fichero con la clave");
        selector.showSaveDialog(ventana);
        if (selector.getSelectedFile() != null) {
            ficheroClave = new File(selector.getSelectedFile().getPath());
            ventana.setTextoConsola("El fichero con la clave se almacenará en:\n" + ficheroOrigen.getPath());
            return true;
        } else {
            return false;
        }
    }

    private static boolean asignarRutaFicheroCodificado() {
        JFileChooser selector = new JFileChooser(rutaFicheroCifrado);
        selector.setDialogTitle("Guardar fichero con la clave de la fase 1 codificada con RSA");
        selector.showSaveDialog(ventana);
        if (selector.getSelectedFile() != null) {
            ficheroCifrado = new File(selector.getSelectedFile().getPath());
            ventana.setTextoConsola("El fichero con codificado se almacenará en:\n" + ficheroOrigen.getPath());
            return true;
        } else {
            return false;
        }
    }

}
