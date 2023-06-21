# PiHole Predict Documentation

## Overview

This project aims to enhance the Pi-hole ad-blocking software by leveraging machine learning techniques to predict and block ads more accurately. This documentation provides an overview of the project, its components, and instructions for usage.

## Table of Contents

1. Installation
2. Usage
3. Files
4. Dependencies
5. Contributing
6. License

## 1. Installation

To install and set up the PiHole Predict project, follow these steps:

1. Clone the project repository from [GitHub](https://github.com/your-username/pihole-predict).
2. Ensure Python 3.x is installed on your system.
3. Install the project dependencies by executing the following command:

```python
pip install -r requirements.txt
```


4. Configure Pi-hole to allow the prediction script to interact with the necessary components. Refer to the project's configuration guide for detailed instructions.

## 2. Usage

To use the PiHole Predict project, follow these steps:

1. Ensure that Pi-hole is up and running.
2. Prepare a CSV file (`domains.csv`) containing a list of domains and IP addresses to be analyzed.
3. Run the prediction script using the following command:

```python
python pihole-predict.py
```


The script will generate predictions for each domain in the input file and save the results to the specified output file.

4. Analyze the generated predictions to gain insights into potential ad-blocking improvements.

## 3. Files

The PiHole Predict project consists of the following files:

- `pihole-predict.py`: The main script that performs ad-blocking predictions based on the provided input file.
- `predict-test.py`: A testing script to validate the functionality of the prediction algorithm.
- `domains.csv`: A sample input file containing a list of domains and IP addresses to be analyzed.
- `requirements.txt`: A file specifying the project's dependencies.

## 4. Dependencies

The PiHole Predict project has the following dependencies, which are automatically installed by running `pip install -r requirements.txt`:

- numpy
- pandas
- scikit-learn

## 5. Contributing

Contributions to the PiHole Predict project are welcome. If you encounter any issues or have suggestions for improvements, please submit them through the project's GitHub repository.

## 6. License

The PiHole Predict project is licensed under the [GNU General Public License (GPL)](https://www.gnu.org/licenses/gpl-3.0.en.html). Please refer to the project's repository for more information.
