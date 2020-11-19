package src;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class CheckUsers {
	private Map<String, String> userNPass = new HashMap<>();;

	public CheckUsers() {
		super();
		this.userNPass = new HashMap<String, String>();
	}

	public Integer checkUser(String username, String pass) {
		Properties prop = new Properties();
		try {
			FileInputStream ip = new FileInputStream("src//users.properties");
			try {
				prop.load(ip);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				System.out.println(e.getMessage());
			}
		} catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
		}

		return 0;
	}

	public Map<String, String> CSVReader() {
		String csvFile = "src//users.csv";
		String line = "";
		String cvsSplitBy = ",";

		try (BufferedReader br = new BufferedReader(new FileReader(csvFile))) {

			while ((line = br.readLine()) != null) {

				String[] country = line.split(cvsSplitBy);
				userNPass.put(country[0], country[1]);
				// System.out.println("Country [code= " + country[0] + " , name=" + country[1] +
				// "]");

			}

		} catch (IOException e) {
			e.printStackTrace();
		}
		return userNPass;

	}
}
