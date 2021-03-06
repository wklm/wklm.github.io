#include <iostream>
#include <fstream>
#include <sstream>
using namespace std;

void print(int n, double * c, int k, double ** A, double * b) {
	cout << "**C MATRIX**\n";
	for(int i = 0; i < n; ++i) {
		cout << c[i] << "\t";
	}
	cout << "\n**A MATRIX**\n";
	for(int i = 0; i < k; ++i) {
		for(int j = 0; j < n; ++j) {
			cout << A[i][j] << "\t";
		}
		cout << endl;
	}
	cout << "**B MATRIX**\n";
	for(int i = 0; i < k + 1; ++i) {
		cout << b[i] << "\t";
	}
	cout << endl;
}

//returns the minimum value in the c array (useful for pivot column identification)
double findMin(double * c, int n) {
	double temp = c[0];
	for(int i = 0; i < n; ++i) {
		if(c[i] < temp) {
			temp = c[i];
		}
	}
	cout << "** Minimum: " << temp << " **" << endl;
	return temp;
}

//returns tempN (old value of n), or 0. tempN is needed when creating the soution array
int bigM(int& n, double *& c, int& k, double **& A, double *& b) {
	int negCounter = 0;
	//count negative bi
	for(int i = 0; i < k; ++i) {
		if(b[i] < 0) {
			++negCounter;
		}
	}
	//in case negatives exist, but are less than k (in case of negatives == k --> Dual Simplex)
	if(negCounter != 0 && negCounter < k) {
		int M = 10000000;
		int * negIndex = new int[negCounter]();
		int temp = 0;
		//find negative bi, and store index i in an array tracker
		for(int i = 0; i < k; ++i) {
			if(b[i] < 0) {
				negIndex[temp] = i;
				++temp;
			}
		}
		//multiply the negative bi contsraints by -1
		for(int i = 0; i < negCounter; ++i) {
			b[negIndex[i]] = -b[negIndex[i]];
			for(int j = 0; j < n; ++j) {
				A[negIndex[i]][j] = -A[negIndex[i]][j];
			}
		}
		int tempN = n;
		n = n + negCounter;
		double * tempC = c;
		//update c
		c = new double[n]();
		for(int i = 0; i < tempN; ++i) {
			c[i] = tempC[i];
		}
		for(int i = tempN; i < n; ++i) {
			c[i] = M;
		}
		//update A
		double ** tempA = A;
		A = new double*[k];
		for(int i = 0; i < k; ++i) {
			 A[i] = new double[n]();
		}
		for(int i = 0; i < k; ++i) {
			int j = 0;
			while(j < tempN) {
				A[i][j] = tempA[i][j];
				++j;
			}
		}
		//update slack variables in the corresponding, previously negative, constraints
		for(int i = 0; i < negCounter; ++i) {
			A[negIndex[i]][tempN + i] = 1;
		}
		//add to bi and ci the -Mth A and b matrix values on negative bi positions
		for(int i = 0; i < negCounter; ++i) {
			b[k] = b[k] + (-M * b[negIndex[i]]);
			for(int j = 0; j < n; ++j) {
				c[j] = c[j] + (-M * A[negIndex[i]][j]);
			}
		}
		cout << "**BIG M METHOD**" << endl;
		print(n, c, k, A, b);
		return tempN;
	}
	return 0;
}

//passing arrays and variables by reference, so they can be changed if needed
bool dualSimplex(int& n, double *& c, int& k, double **& A, double *& b) {
	//check if all bi in array b are negative (dual simplex required if so)
	int negCounter = 0;
	for(int i = 0; i < k; ++i) {
		if(b[i] < 0) {
			++negCounter;
		}
	}
	if(negCounter == k) {
		//swap the values of n and k (n is actually n + k)
		int tempK = k;
		k = n - k;
		n = tempK + k;
		//keep old b values in a temp array
		double * tempB = b;
		//update b (corresponds to the dual c matrix from the OPS script)
		b = new double[k + 1]();
		for(int i = 0; i < k; ++i) {
			b[i] = c[i];
		}
		//update c (corresponds to the dual b matrix from the OPS script)
		c = new double[n]();
		for(int i = 0; i < tempK; ++i) {
			c[i] = tempB[i];
		}
		//transpone matrix A
		double ** tempA = A;
		A = new double*[k];
		for(int i = 0; i < k; ++i) {
			 A[i] = new double[n]();
		}
		for(int i = 0; i < k; ++i) {
			int j = 0;
			while(j < n - k) {
				A[i][j] = -tempA[j][i];
				++j;
			}
			A[i][j + i] = 1;
		}
		cout << "**DUAL SIMPLEX**" << endl;
		print(n, c, k, A, b);
		return true;
	}
	return false;
}

double * lpsolve(int n, double * c, int k, double ** A, double * b) {
	//check for dual simplex
	bool dual = dualSimplex(n, c, k, A, b);
	int tempN = 0;
	//check for big M method
	if(!dual) {
		tempN = bigM(n, c, k, A, b);
	}
	double min;
	//create solution array accordingly
	double * solution;
	if(tempN > 0) {
		solution = new double [tempN + 1]();
	} else {
		solution = new double [n + 1]();
	}
	//array containing indices of solution variables (basis variables)
	int * rowVariableTracker = new int [k];
	for(int i = 0; i < k; ++i) {
		rowVariableTracker[i] = n - k + i + 1;
	}
	while((min = findMin(c, n)) < 0) {
		int pivotColumn;
		for(int i = 0; i < n; ++i) {
			if(c[i] == min) {
				pivotColumn = i;
			}
		}
		bool pivotRowSet = false;
		int pivotRowDiv;
		int pivotRow;
		double pivot;
		//finding the pivot
		for(int i = 0; i < k; ++i) {
			if(A[i][pivotColumn] != 0 && A[i][pivotColumn] > 0) {
				if(!pivotRowSet) {
					pivotRowDiv = b[i] / A[i][pivotColumn];
					pivotRow = i;
					pivot = A[i][pivotColumn];
					pivotRowSet = true;
				}
				if(b[i] / A[i][pivotColumn] < pivotRowDiv) {
					pivotRowDiv = b[i] / A[i][pivotColumn];
					pivotRow = i;
					pivot = A[i][pivotColumn];
				}
			}
		}
		if(!pivotRowSet) {
			cout << "There is no optimal solution to this function!" << endl;
			return 0;
		}
		cout << "-> Pivot Column:" << pivotColumn << endl;
		cout << "-> Pivot Row:   " << pivotRow << endl;
		rowVariableTracker[pivotRow] = pivotColumn + 1;
		double divisor;
		double functionDivisor = c[pivotColumn] / pivot;

		//subtracting the pivot row (multiplied with divisor) from every A matrix row (except the pivot row)
		for(int i = 0; i < k; ++i) {
			if(i == pivotRow) {
				continue;
			} else {
				divisor = A[i][pivotColumn] / pivot;
			}
			for(int j = 0; j < n; ++j) {
				A[i][j] = A[i][j] - (divisor * A[pivotRow][j]);
			}
			b[i] = b[i] - (divisor * b[pivotRow]);
		}

		//function value at b 
		b[k] = b[k] - (functionDivisor * b[pivotRow]);

		//modifying c
		for(int i = 0; i < n; ++i) {
			c[i] = c[i] - (functionDivisor * A[pivotRow][i]);
		}

		//modifying b at the pivotRow index
		b[pivotRow] = b[pivotRow] / pivot;

		//dividing the pivot row by the pivot value
		for(int i = 0; i < n; ++i) {
			A[pivotRow][i] = A[pivotRow][i] / pivot;
		}
		cout << "**WORKING ON IT**" << endl;
		print(n, c, k, A, b);
	}
	if(dual) {
		cout << "**The DUAL SIMPLEX has been applied**" << endl;
		cout << "The solution to the dual problem of the dual problem, therefore to the primal problem is [ ";
		for(int i = n - k; i < n; ++i) {
			cout << c[i] << " ";
		}
		cout << "]" << endl;
		cout << "This is also how sensitive the objective function reacts to changes in constraint bi values" << endl;
		return 0;
	}
	//Sensitivity (big M and normal case)
	if(tempN > 0) {
		int slackCounter = 0;
		for(int i = tempN; i < n; ++i) {
			for(int j = 0; j < k; ++j) {
				if((rowVariableTracker[j] - 1) == i) {
					++slackCounter;
				}
			}
		}
		if(slackCounter == 0) {
			cout << "**SENSITIVITY** [ ";
			for(int i = tempN - k; i < tempN; ++i) {
				cout << c[i] << " ";
			}
			cout << "]" << endl;
			cout << "The objective function is this sensitive to changes in constraint bi values" << endl;
		} else {
			cout << "The given program has no solution!" << endl;
			return 0;
		}
	} else {
		cout << "**SENSITIVITY** [ ";
		for(int i = n - k; i < n; ++i) {
			cout << c[i] << " ";
		}
		cout << "]" << endl;
		cout << "The objective function is this sensitive to changes in constraint bi values" << endl;
	}
	for(int i = 0; i < k; ++i) {
		solution[rowVariableTracker[i] - 1] = b[i];
	}
	if(tempN > 0) {
		solution[tempN] = b[k];
	} else {
		solution[n] = b[k];
	}
	return solution;
}

int main(int argc, char* argv[]) {
	string path, temp;
	int ivar, n, k, oldN;
	n = k = 0;
	double dvar;
	double * b, * c;
	double ** A;
	istringstream iss;
	if(argc < 2) {
		cerr << "Usage: " << argv[0] << " PATH" << endl;
		return 1;
	}
	path = argv[1];
	//open file and read data (output errors if needed)
	fstream file(path.c_str()); 
	if(file.is_open()) {
		if(getline(file,temp)) {
			iss.str(temp);
			int frcounter = 0;
			while(iss >> ivar) {
				if(frcounter > 1) {
					cout << "Oops, the first row of the file must not contain more than 2 space delimited numbers;\n";
					cout << "Modify or change the file, then try again...";
					return 0;
				}
				if(frcounter == 0) {
					n = ivar;
				} else {
					k = ivar;
				}
				++frcounter;
			}
			if(n == 0 || k == 0) {
				cout << "Oops, the first row of the file must contain 2 space delimited numbers;\n";
				cout << "Modify or change the file, then try again...";
				return 0;
			}
			//stores the initial value of n
			oldN = n;
			n = n + k;
			A = new double*[k];
			for(int i = 0; i < k; ++i) {
				A[i] = new double[n]();
			}
			b = new double [k + 1]();
			c = new double [n]();
		} else { cout << "The file/PATH is corrupted!"; return 0; }
		if(getline(file,temp)) {
			iss.str(temp);
			iss.clear();
			int ncounter = 0;
			while(iss >> dvar) {
				if(ncounter > oldN) {
					cout << "The number of variables exceeds the one specified in row one (variable | n | is being violated);\n";
					cout << "Edit the file so that | n | and the number of variables rows are equal, then try again...";
					return 0;
				}
				if(dvar != 0) {
					c[ncounter] = dvar * -1;
				}
				++ncounter;
			}
		}
		int kcounter = 0;
		while(getline(file,temp)) {
			if(kcounter > k) {
				cout << "The number of constraints exceeds the one specified in row one (variable | k | is being violated);\n";
				cout << "Edit the file so that | k | and the number of constraint rows are equal, then try again...";
				return 0;
			}
			iss.str(temp);
			iss.clear();
			int ncounter = 0;
			while(iss >> dvar) {
				if(ncounter > oldN + 1) {
					cout << "The number of variables exceeds the one specified in row one (variable | n | is being violated);\n";
					cout << "Edit the file so that | n | is not exceeded by the number of variables in a row (excluding | b | variables), then try again...";
					return 0;
				}
				A[kcounter][ncounter] = dvar;
				++ncounter;
			}
			/*correction is the index of the last element in A vertically, for the given kcounter horizontal position
			  each row from the file is first stored in A
			  then the last element from each row gets stored in b
			*/
			int correction = --ncounter;
			b[kcounter] = A[kcounter][correction];
			A[kcounter][correction] = 0;
			++kcounter;
		}
		//identity matrix for A
		for(int i = 0; i < k; ++i) {
			A[i][oldN + i] = 1;
		}
	} else {
		cout << "Invalid file path!" << endl;
		return 0;
	}
	cout << "**RAW DATA**" << endl;
	print(n, c, k, A, b);
	double * solution = lpsolve(n, c, k, A, b);
	if(solution != 0) {
		cout << "The optimum of the processed function should lie on the points" << endl;
		cout << "[ ";
		for(int i = 0; i < n; ++i) {
			cout << solution[i] << " ";
		}
		cout << "]" << endl;
		cout << "where the function would take on a value of [ " << solution[n] << " ]" << endl;
		cout << "Hopefully that helped!";
	}
	
	file.close();
	return 0;
}