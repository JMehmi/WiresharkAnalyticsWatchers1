import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ListIterator;
import java.util.Scanner;

import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;

/*
 * For launching this software there are 4 ways
 * 1) Launch the software only with the "watch" configuration so that the watchers will be enabled in the local directory
 * 2) Launch the software with the "watch" configuration and the path of the directory to watch
 * 3) Launch the software only with the path of the file  to process
 * 4) Launch the software and it will ask you for the path of the file to process
 */
public class Main {

	// Declaring the variables for the indexes
	static int NO_INDEX = -1;
	static int TIME_INDEX = -1;
	static int SOURCE_INDEX = -1;
	static int DESTINATION_INDEX = -1;
	static int PROTOCOL_INDEX = -1;
	static int LENGTH_INDEX = -1;
	static int IP_LENGTH_INDEX = -1;
	static int TCP_LENGTH_INDEX = -1;
	static int HTTP_LENGTH_INDEX = -1;
	static int INFO_INDEX = -1;
	static int FILE_DATA_INDEX = -1;
	static int TCP_SEQ_INDEX = -1;
	static int TCP_NEXT_SEQ_INDEX = -1;

	public static void main(String[] args) throws IOException, InterruptedException {

		String csvFilePath = "";
		String outputNameFile = "";
		String inputNameFile = "";
		String filePath = "";

		// Start
		System.out.println("Start");

		if (args.length > 0) {
			// if only watch parameter
			if (args[0].equals("watch")) {
				if (args.length == 1) {
					csvFilePath = new java.io.File(".").getCanonicalPath();
				}
				// if watch parameter + directory path
				else {
					csvFilePath = args[1];
				}
				System.out.println("Watching directory " + csvFilePath);
				System.out.println("...");

				Path dir = Paths.get(csvFilePath);
				// Declaring a new watcher
				final WatchService watcher = dir.getFileSystem().newWatchService();
				// Which event the watcher have to check
				dir.register(watcher, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);

				while (true) {

					final WatchKey wk = watcher.take();
					for (WatchEvent<?> event : wk.pollEvents()) {

						if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE
								|| event.kind() == StandardWatchEventKinds.ENTRY_MODIFY) {

							// Getting the path of the new or modified file
							Path changed = (Path) event.context();

							int x = changed.toString().lastIndexOf(".csv");

							if (x > 1) {

								inputNameFile = changed.toString();

								outputNameFile = inputNameFile.replace(".csv", ".d2c");
								// Processing the file
								ProcessData(csvFilePath + "/" + inputNameFile, csvFilePath + "/" + outputNameFile);
							}
						}

					}
					wk.reset();
				}

			}
			// if argument = file input path
			else {

				if (args.length > 0)

					for (int i = 0; i < args.length; i++) {
						if (i > 0) {
							csvFilePath += " ";
						}
						csvFilePath += args[i];
					}
				System.out.println("Csv file path = " + csvFilePath);
				
				File f = new File(csvFilePath);
				
				if (!f.exists()) {
				
					System.out.println("Wrong path");
					
					System.exit(0);
				}
				
				int indexSlash = csvFilePath.lastIndexOf("/");
				indexSlash = indexSlash < 0 ? 0 : indexSlash + 1;
				inputNameFile = csvFilePath.substring(indexSlash, csvFilePath.lastIndexOf("."));
				filePath = csvFilePath.substring(0, indexSlash);
				outputNameFile = inputNameFile + ".d2c";
				//Processing the File
				ProcessData(csvFilePath, filePath + outputNameFile);
			}
		} else {
			while (args.length == 0) {
				System.out.println("Specificare il file di origine");
				Scanner sc = new Scanner(System.in);
				String str = sc.nextLine();
				File f = new File(str);
				if (!f.exists()) {
					System.out.println("Wrong path");
				} else {
					csvFilePath = str;
					int indexSlash = csvFilePath.lastIndexOf("/");
					indexSlash = indexSlash < 0 ? 0 : indexSlash + 1;
					inputNameFile = csvFilePath.substring(indexSlash, csvFilePath.lastIndexOf("."));
					filePath = csvFilePath.substring(0, indexSlash);
					outputNameFile = inputNameFile + ".d2c";
					//Processing the File
					ProcessData(csvFilePath, filePath + outputNameFile);
					break;
				}
			}
		}
	} // end main

	/**
	 * The function ProcessData, gets the .csv file and iterate till it finds
	 * the Http packet then it saves the index of the packet and goes back till
	 * next sequence number is equal to 1 it makes the sum of the lengths of the
	 * different packets and then return the total thought the calcTotals
	 * function
	 * 
	 * @param csvFilePath
	 * @param outputNameFile
	 * @throws IOException
	 */
	private static void ProcessData(String csvFilePath, String outputNameFile) throws IOException {
		CSVReader reader = new CSVReader(new FileReader(csvFilePath), ',');

		// all entries
		List<String[]> myEntries = reader.readAll();

		List<HashMap<String, Object>> results = new ArrayList<HashMap<String, Object>>();

		ListIterator<String[]> itMain = myEntries.listIterator();

		// Getting the index from the headers
		GetIndex(itMain);

		// read header values
		while (itMain.hasNext()) {
			String[] record = itMain.next();

			// HTTP node
			if (record[PROTOCOL_INDEX] != null && record[PROTOCOL_INDEX].trim().equals("HTTP")) {
				// httpLengthTOT
				int httpLengthTOT = Integer.parseInt(record[HTTP_LENGTH_INDEX]);

				// pTipAction
				String fileData = record[FILE_DATA_INDEX];
				String[] fileDataArray = fileData.split("&", -1);
				String fileDataVal = null;
				for (String data : fileDataArray) {
					if (data.split("=", -1)[0].equals("pTipAction")) {
						fileDataVal = data.split("=", -1)[1];
						break;
					}
				}

				// init hashMap
				HashMap<String, Object> hmTotal = new HashMap<String, Object>();
				hmTotal.put("no", record[NO_INDEX]);
				hmTotal.put("source", record[SOURCE_INDEX]);
				hmTotal.put("fileDataVal", fileDataVal);
				hmTotal.put("length", Integer.parseInt(record[LENGTH_INDEX]));
				hmTotal.put("ipLength", Integer.parseInt(record[IP_LENGTH_INDEX]));
				hmTotal.put("tcpLength", Integer.parseInt(record[TCP_LENGTH_INDEX]));
				hmTotal.put("httpDataLength", httpLengthTOT);
				hmTotal.put("fileData", fileData);
				hmTotal.put("packets", 1);

				// calc totals values
				hmTotal = calcTotals(myEntries, record, hmTotal, itMain);

				results.add(hmTotal);
			}
		}

		reader.close();

		CSVWriter writer = new CSVWriter(new FileWriter(outputNameFile), ',');
		// row header
		writer.writeNext(new String[] { "No.", "Source", "Command", "Frame Length", "IP Length", "TCP Length",
				"HTTP Data Length", "Packets", "File Data" });
		// row values
		for (int i = 0; i < results.size(); i++) {
			HashMap<String, Object> rowItem = results.get(i);
			String[] arr = new String[9];
			arr[0] = rowItem.get("no").toString();
			arr[1] = rowItem.get("source").toString();
			arr[2] = rowItem.get("fileDataVal").toString();
			arr[3] = rowItem.get("length").toString();
			arr[4] = rowItem.get("ipLength").toString();
			arr[5] = rowItem.get("tcpLength").toString();
			arr[6] = rowItem.get("httpDataLength").toString();
			arr[7] = rowItem.get("packets").toString();
			arr[8] = rowItem.get("fileData").toString();
			writer.writeNext(arr);
		}
		writer.close();
		System.out.println("\nResult Csv file path = " + outputNameFile);
	} // end ProcessData

	/**
	 * This function receive the first line that's the header of the.csv files
	 * and get the index of the different columns
	 * 
	 * @param itMain
	 */

	private static void GetIndex(ListIterator<String[]> itMain) {
		String[] header = itMain.next();
		int index = 0;
		// header row
		for (String colHeader : header) {
			switch (colHeader) {
			case "No.":
				NO_INDEX = index;
				break;
			case "Time":
				TIME_INDEX = index;
				break;
			case "Source":
				SOURCE_INDEX = index;
				break;
			case "Destination":
				DESTINATION_INDEX = index;
				break;
			case "Protocol":
				PROTOCOL_INDEX = index;
				break;
			case "Length":
				LENGTH_INDEX = index;
				break;
			case "IP Len":
				IP_LENGTH_INDEX = index;
				break;
			case "TCP Len":
				TCP_LENGTH_INDEX = index;
				break;
			case "HTTP Data Len":
				HTTP_LENGTH_INDEX = index;
				break;
			case "Info":
				INFO_INDEX = index;
				break;
			case "File Data":
				FILE_DATA_INDEX = index;
				break;
			case "TCP Seq":
				TCP_SEQ_INDEX = index;
			case "TCP Next Seq":
				TCP_NEXT_SEQ_INDEX = index;
				break;
			}
			index++;
		}
	} // end index

	/**
	 * This function is called by the ProcessData function for doing the total
	 * sums of the lengths and its recursive
	 * 
	 * @param myEntries
	 * @param record
	 * @param hmTotal
	 * @param mainIterator
	 * @return
	 */
	private static HashMap<String, Object> calcTotals(List<String[]> myEntries, String[] record,
			HashMap<String, Object> hmTotal, ListIterator<String[]> mainIterator) {

		// if it's the last packets it stops the search
		if (record[TCP_SEQ_INDEX].equals("1")) {
			return hmTotal;
		}

		// start
		ListIterator<String[]> itChild = myEntries.listIterator(mainIterator.nextIndex() - 1);
		// Search for the packets with TCPinit = TCPnext (record)
		while (itChild.hasPrevious()) {
			String[] recordNext = itChild.previous();
			// check if the package is same as the upper line
			if (Integer.parseInt(record[TCP_NEXT_SEQ_INDEX]) > 1 && record[TCP_SEQ_INDEX] != null
					&& recordNext[TCP_NEXT_SEQ_INDEX] != null
					&& recordNext[TCP_NEXT_SEQ_INDEX].equals(record[TCP_SEQ_INDEX])
					&& record[SOURCE_INDEX].equals(recordNext[SOURCE_INDEX])
					&& record[DESTINATION_INDEX].equals(recordNext[DESTINATION_INDEX])) {
				// sum
				hmTotal.put("length", Integer.parseInt(hmTotal.get("length").toString())
						+ Integer.parseInt(recordNext[LENGTH_INDEX]));
				hmTotal.put("ipLength", Integer.parseInt(hmTotal.get("ipLength").toString())
						+ Integer.parseInt(recordNext[IP_LENGTH_INDEX]));
				hmTotal.put("tcpLength", Integer.parseInt(hmTotal.get("tcpLength").toString())
						+ Integer.parseInt(recordNext[TCP_LENGTH_INDEX]));
				hmTotal.put("packets", Integer.parseInt(hmTotal.get("packets").toString()) + 1);

				// continue the search
				return calcTotals(myEntries, recordNext, hmTotal, mainIterator);
			}
		}

		return hmTotal;
	} // end calcTotals

}// end class Main
 