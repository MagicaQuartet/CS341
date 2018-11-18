x = 1

while ./build/testTCP --gtest_filter="*Transfer*";
do
	x=$(( $x + 1 ))
	echo "$x times test passed!"
	sleep 1;
done
