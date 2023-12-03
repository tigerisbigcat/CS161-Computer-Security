package client_test

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports. Normally, you will want to avoid underscore imports
	// unless you know exactly what you are doing. You can read more about
	// underscore imports here: https://golangdocs.com/blank-identifier-in-golang

	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect(). You can read more
	// about dot imports here:
	// https://stackoverflow.com/questions/6478962/what-does-the-dot-or-period-in-a-go-import-statement-do

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	// The client implementation is intentionally defined in a different package.
	// This forces us to follow best practice and write tests that only rely on
	// client API that is exported from the client package, and avoid relying on
	// implementation details private to the client package.
	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	// We are using 2 libraries to help us write readable and maintainable tests:
	//
	// (1) Ginkgo, a Behavior Driven Development (BDD) testing framework that
	//             makes it easy to write expressive specs that describe the
	//             behavior of your code in an organized manner; and
	//
	// (2) Gomega, an assertion/matcher library that allows us to write individual
	//             assertion statements in tests that read more like natural
	//             language. For example "Expect(ACTUAL).To(Equal(EXPECTED))".
	//
	// In the Ginko framework, a test case signals failure by calling Ginkgo’s
	// Fail(description string) function. However, we are using the Gomega library
	// to execute our assertion statements. When a Gomega assertion fails, Gomega
	// calls a GomegaFailHandler, which is a function that must be provided using
	// gomega.RegisterFailHandler(). Here, we pass Ginko's Fail() function to
	// Gomega so that Gomega can report failed assertions to the Ginko test
	// framework, which can take the appropriate action when a test fails.
	//
	// This is the sole connection point between Ginkgo and Gomega.
	RegisterFailHandler(Fail)

	RunSpecs(t, "Client Tests")
}

// ================================================
// Here are some optional global variables that can be used throughout the test
// suite to make the tests more readable and maintainable than defining these
// values in each test. You can add more variables here if you want and think
// they will help keep your code clean!
// ================================================
const someFilename = "file1.txt"
const someOtherFilename = "file2.txt"
const nonExistentFilename = "thisFileDoesNotExist.txt"

const aliceUsername = "Alice"
const alicePassword = "AlicePassword"
const bobUsername = "Bob"
const bobPassword = "BobPassword"
const nilufarUsername = "Nilufar"
const nilufarPassword = "NilufarPassword"
const olgaUsername = "Olga"
const olgaPassword = "OlgaPassword"
const marcoUsername = "Marco"
const marcoPassword = "MarcoPassword"

const nonExistentUsername = "NonExistentUser"

var alice *client.User
var bob *client.User
var nilufar *client.User
var olga *client.User
var marco *client.User

var someFileContent []byte
var someShortFileContent []byte
var someLongFileContent []byte

// ================================================
// The top level Describe() contains all tests in
// this test suite in nested Describe() blocks.
// ================================================

var _ = Describe("Client Tests", func() {
	BeforeEach(func() {
		// This top-level BeforeEach will be run before each test.
		//
		// Resets the state of Datastore and Keystore so that tests do not
		// interfere with each other.
		userlib.DatastoreClear()
		userlib.KeystoreClear()

		userlib.SymbolicDebug = false
		userlib.SymbolicVerbose = false
	})

	BeforeEach(func() {
		// This top-level BeforeEach will be run before each test.
		//
		// Byte slices cannot be constant, so this BeforeEach resets the content of
		// each global variable to a predefined value, which allows tests to rely on
		// the expected value of these variables.
		someShortFileContent = []byte("some short file content")
		someFileContent = someShortFileContent
		someLongFileContent = []byte("some LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file content")
	})

	// 1
	Describe("Creating users", func() {

		// pass 0 1 3 7 11
		It("should error if a username or password is empty", func() {
			_, err := client.InitUser("", "password")
			Expect(err).To(BeNil(), "Empty username is not allowed.")

			_, err1 := client.InitUser("alice", "")
			Expect(err1).To(BeNil(), "Empty password is not allowed.")
		})

		// pass 0 1 3 7 11
		It("should error if a filename or file content is empty", func() {
			alice, _ = client.InitUser(aliceUsername, alicePassword)

			// test for the empty content
			err1 := alice.StoreFile(someFilename, []byte(""))
			Expect(err1).To(BeNil(), "failed to save a file with empty file content.")

			// test for the empty name
			err := alice.StoreFile("", someFileContent)
			Expect(err).To(BeNil(), "failed to save a file with empty filename.")

			_, err = alice.LoadFile("")
			Expect(err).To(BeNil(), "failed to load a file with empty filename.")

			access, err := alice.CreateInvitation("", bobUsername)
			Expect(err).ToNot(BeNil(), "failed to share a file with empty filename.")

			err = bob.AcceptInvitation(aliceUsername, access, "")
			Expect(err).ToNot(BeNil(), "failed to accept a file with empty filename.")

			appendContent := []byte("alice's appending")
			err = alice.AppendToFile("", appendContent)
			Expect(err).To(BeNil(), "failed to append a file with empty filename.")

			err = alice.RevokeAccess("", bobUsername)
			Expect(err).ToNot(BeNil(), "failed to revoke bob from a file with empty filename.")
		})

		// pass 0 1 3 7 11
		It("should error if a username is case sensitive", func() {
			_, err := client.InitUser("alice", "password")
			Expect(err).To(BeNil(), "Failed to check the case sensitive usernames.")

			_, err1 := client.InitUser("alicE", "password")
			Expect(err1).To(BeNil(), "Failed to check the case sensitive usernames.")
		})

		// pass 0 1 3 7 11 13
		It("should error if a user does not exist with that username", func() {
			_, err := client.GetUser("Alexa", "password")
			Expect(len(err.Error())).NotTo(BeZero())

			_, err = client.InitUser(nonExistentUsername, "password")
			Expect(err).To(BeNil(), "Doesn't exist user.")
		})

		It("should error if a username is already taken by another user", func() {
			_, err := client.InitUser("Fred", "password")
			_, err = client.InitUser("Fred", "password")
			Expect(len(err.Error())).NotTo(BeZero())
		})

		It("should error if a user does not exist with that username", func() {
			_, err := client.GetUser("Alexa", "password")
			Expect(len(err.Error())).NotTo(BeZero())
		})

		It("should error if a username with wrong password", func() {
			_, _ = client.InitUser("Fred", "password")
			_, err := client.GetUser("Fred", "123")
			Expect(len(err.Error())).NotTo(BeZero())
		})

		It("should not error if a long username", func() {
			_, err := client.InitUser("CiciCiciCiciCiciCiciCici", "password")
			Expect(err).To(BeNil(), "Failed to initialized user CiciCiciCiciCiciCiciCici.")
		})

		It("should not error if a long username", func() {
			_, err := client.InitUser("Cici", "passwordpasswordpasswordpasswordpasswordpasswordpassword")
			Expect(err).To(BeNil(), "Failed to initialized user Cici.")
		})

		It("should error malicious data happened", func() {
			_, _ = client.InitUser("Alice", "password")
			uuid, _ := userlib.UUIDFromBytes(userlib.Hash([]byte("Alice"))[:16])
			userlib.DatastoreSet(uuid, []byte("Malicious DATA!"))
			_, err := client.GetUser("Alice", "password")
			Expect(len(err.Error())).NotTo(BeZero())
		})
	})

	// 2
	Describe("Get users", func() {

		// doesn't count
		It("should not error when getting a user", func() {
			_, err := client.InitUser("Alice", "password")
			Expect(err).To(BeNil(), "Failed to initialized user Alice.")

			_, err = client.GetUser("Alice", "password")
			Expect(err).To(BeNil(), "Failed to get user Alice.")

			_, err = client.GetUser("Alice", "xxxxxx")
			Expect(err).ToNot(BeNil(), "Failed to check the password.")

			_, err = client.GetUser("Alicexxxxx", "password")
			Expect(err).ToNot(BeNil(), "Failed to check the username.")

			_, err = client.GetUser("Alicexxxxx", "xxxxxxx")
			Expect(err).ToNot(BeNil(), "Failed to check the username and password.")
		})
	})

	// 3
	Describe("Single user storage", func() {
		// var alice *client.User

		BeforeEach(func() {
			// This BeforeEach will run before each test in this Describe block.
			alice, _ = client.InitUser("Alice", "sp")
			bob, _ = client.InitUser(bobUsername, bobPassword)
		})

		// doesn't count
		It("should has an error when someone change the data", func() {
			data := userlib.DatastoreGetMap()
			dataOriginal := make(map[uuid.UUID][]byte)
			for k, v := range data {
				dataOriginal[k] = v
			}

			content := []byte("It's alice's file content.")
			err := alice.StoreFile(someFilename, content)
			Expect(err).To(BeNil(), "Failed to store alice's file.")

			data = userlib.DatastoreGetMap()
			dataOriginal1 := make(map[uuid.UUID][]byte)
			for k, v := range data {
				dataOriginal1[k] = v
			}

			difference := []uuid.UUID{}

			for k := range dataOriginal1 {
				if _, ok := dataOriginal1[k]; !ok {
					difference = append(difference, k)
				}
			}

			for i := 0; i < len(difference)-1; i++ {
				content1 := difference[i]
				content10, _ := userlib.DatastoreGet(content1)
				content2 := difference[i+1]
				content20, _ := userlib.DatastoreGet(content2)

				userlib.DatastoreSet(content1, content20)
				userlib.DatastoreSet(content2, content10)

				_, err = alice.LoadFile(someFilename)
				Expect(err).To(BeNil(), "Failed to detecte the content changes.")

				userlib.DatastoreSet(content1, content10)
				userlib.DatastoreSet(content2, content20)
			}
		})

		// Different users can store files using the same filename because
		// each user must have a separate personal file namespace.
		// pass 0 1 3 7 11 13  doesn't count
		It("test the same filename but different content for different users", func() { // todo
			content1 := []byte("alice's content.")
			err1 := alice.StoreFile(someFilename, content1)
			Expect(err1).To(BeNil(), "Failed to upload content to a file.")

			downloading1, err := alice.LoadFile(someFilename)
			Expect(err).To(BeNil(), "failed to upload and download")
			Expect(downloading1).To(BeEquivalentTo(content1),
				"Downloaded content is not the same as uploaded content")

			content2 := []byte("bob's content")
			err2 := bob.StoreFile(someFilename, content2)
			Expect(err2).To(BeNil(), "Failed to upload content to a file.")

			downloading2, err := bob.LoadFile(someFilename)
			Expect(err).To(BeNil(), "failed to upload and download")
			Expect(downloading1).To(BeEquivalentTo(content1),
				"Downloaded content is not the same as uploaded content")

			Expect(downloading1).ToNot(BeEquivalentTo(downloading2),
				"same filename but different users should have different content.")
		})

		// pass 0 1 2 3 7 11 12 13 19   2 12 19
		It("should upload content without erroring", func() {
			content := []byte("This is a test")
			err := alice.StoreFile("file1", content)
			Expect(err).To(BeNil(), "Failed to upload content to a file", err)
		})

		It("should upload content without erroring", func() {
			content := []byte("This is a test")
			_ = alice.StoreFile("file1", content)
			err := alice.StoreFile("file1", content)
			Expect(err).To(BeNil(), "Failed to upload content to a file", err)
		})

		It("should download the expected content that was previously uploaded", func() {
			uploadedContent := []byte("This is a test")
			alice.StoreFile(someFilename, uploadedContent)
			downloadedContent, _ := alice.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)
		})

		It("long file should download the expected content that was previously uploaded", func() {
			uploadedContent := someLongFileContent
			alice.StoreFile(someFilename, uploadedContent)
			downloadedContent, _ := alice.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)
		})

		It("should download the expected content that was previously uploaded", func() {
			uploadedContent1 := []byte("This is a test")
			uploadedContent2 := []byte("This is a test")
			alice.StoreFile(someFilename, uploadedContent1)
			alice.StoreFile(someFilename, uploadedContent2)
			downloadedContent, _ := alice.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent2),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent2)
		})

		It("should error when trying to download a file that does not exist", func() {
			_, err := alice.LoadFile(nonExistentFilename)
			Expect(err).ToNot(BeNil(), "Was able to load a non-existent file without error.")
		})

		It("different devices does not make difference", func() {
			content := []byte("This is a test")
			a2, _ := client.GetUser(aliceUsername, "sp")
			alice.StoreFile(someFilename, content)
			downloadedContent, _ := a2.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(content),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				content)
		})

		It("should ok append file and load test", func() {
			content := []byte("This is a test")
			content1 := []byte("0")
			content2 := []byte("1")
			content3 := []byte("2")
			alice.StoreFile(someFilename, content)
			alice.AppendToFile(someFilename, content1)
			alice.AppendToFile(someFilename, content2)
			alice.AppendToFile(someFilename, content3)
			downloadedContent, _ := alice.LoadFile(someFilename)
			content = []byte("This is a test012")
			Expect(downloadedContent).To(BeEquivalentTo(content),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				content)
		})

		It("should ok append nothing and load test", func() {
			content := []byte("This is a test")
			content1 := []byte("")
			content2 := []byte("")
			alice.StoreFile(someFilename, content)
			alice.AppendToFile(someFilename, content1)
			alice.AppendToFile(someFilename, content2)
			downloadedContent, _ := alice.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(content),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				content)
		})

		It("should error append file to dne file", func() {
			content1 := []byte("0")
			err := alice.AppendToFile(someFilename, content1)
			Expect(len(err.Error())).NotTo(BeZero())
		})
	})

	// total pass 0 1 2 3 4 5 6 7 8 11 12 13 14 18 19 22
	// 4    this block pass 4 5 6 8 14 18 22
	Describe("Sharing files", func() {
		BeforeEach(func() {
			// Initialize each user to ensure the variable has the expected value for
			// the tests in this Describe() block.
			alice, _ = client.InitUser(aliceUsername, alicePassword)
			bob, _ = client.InitUser(bobUsername, bobPassword)
			nilufar, _ = client.InitUser(nilufarUsername, nilufarPassword)
			olga, _ = client.InitUser(olgaUsername, olgaPassword)
			marco, _ = client.InitUser(marcoUsername, marcoPassword)
		})

		It("should share invitation without erroring", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			_, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")
		})

		It("should error share invitation of a DNE file", func() {
			_, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).NotTo(BeNil(), "Alice failed to share a file with Bob.")
		})

		It("should share and accept invitation without erroring", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the invitation that Alice shared.")
		})

		It("should share a file without erroring each append", func() {
			content := []byte("HELLO ITS ME")
			alice.StoreFile(someFilename, content)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			content2 := []byte("012")
			err = bob.AppendToFile(someOtherFilename, content2)
			Expect(err).To(BeNil(), "Bob could not append to the file.")

			content3 := []byte("111")
			err = alice.AppendToFile(someFilename, content3)
			Expect(err).To(BeNil(), "Alice could not append to the file.")

			fcontent := []byte("HELLO ITS ME012111")
			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(fcontent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")
		})

		It("should share a file without erroring each append", func() {
			content := []byte("HELLO ITS ME")
			alice.StoreFile(someFilename, content)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			shareFileInfoPtr2, err := alice.CreateInvitation(someFilename, olgaUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Olga.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			err = olga.AcceptInvitation(aliceUsername, shareFileInfoPtr2, "olgaFile")
			Expect(err).To(BeNil(), "Olga could not receive the file that Alice shared.")

			content2 := []byte("012")
			err = bob.AppendToFile(someOtherFilename, content2)
			Expect(err).To(BeNil(), "Bob could not append to the file.")

			content3 := []byte("111")
			err = alice.AppendToFile(someFilename, content3)
			Expect(err).To(BeNil(), "Alice could not append to the file.")

			content4 := []byte("222")
			err = olga.AppendToFile("olgaFile", content4)
			Expect(err).To(BeNil(), "Olga could not append to the file.")

			fcontent := []byte("HELLO ITS ME012111222")
			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(fcontent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")

			downloadedContent2, err := olga.LoadFile("olgaFile")
			Expect(err).To(BeNil(), "Olga could not load the file that Alice shared.")
			Expect(downloadedContent2).To(BeEquivalentTo(fcontent),
				"The file contents that Olga downloaded was not the same as what Alice uploaded.")

			downloadedContent3, err := alice.LoadFile(someFilename)
			Expect(err).To(BeNil(), "Alice could not load the file that Alice shared.")
			Expect(downloadedContent3).To(BeEquivalentTo(fcontent),
				"The file contents that Alice downloaded was not the same as what Alice uploaded.")
		})

		It("should share share a file without erroring each append", func() {
			content := []byte("HELLO ITS ME")
			alice.StoreFile("af", content)
			shareFileInfoPtr, err := alice.CreateInvitation("af", bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, "bf")
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			shareFileInfoPtr2, err := bob.CreateInvitation("bf", olgaUsername)
			Expect(err).To(BeNil(), "Bob failed to share a file with Olga.")

			err = olga.AcceptInvitation(bobUsername, shareFileInfoPtr2, "of")
			Expect(err).To(BeNil(), "Olga could not receive the file that Alice shared.")

			content2 := []byte("012")
			err = bob.AppendToFile("bf", content2)
			Expect(err).To(BeNil(), "Bob could not append to the file.")

			content3 := []byte("111")
			err = alice.AppendToFile("af", content3)
			Expect(err).To(BeNil(), "Alice could not append to the file.")

			content4 := []byte("222")
			err = olga.AppendToFile("of", content4)
			Expect(err).To(BeNil(), "Olga could not append to the file.")

			fcontent := []byte("HELLO ITS ME012111222")
			downloadedContent, err := bob.LoadFile("bf")
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(fcontent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")

			downloadedContent2, err := olga.LoadFile("of")
			Expect(err).To(BeNil(), "Olga could not load the file that Alice shared.")
			Expect(downloadedContent2).To(BeEquivalentTo(fcontent),
				"The file contents that Olga downloaded was not the same as what Alice uploaded.")

			downloadedContent3, err := alice.LoadFile("af")
			Expect(err).To(BeNil(), "Alice could not load the file that Alice shared.")
			Expect(downloadedContent3).To(BeEquivalentTo(fcontent),
				"The file contents that Alice downloaded was not the same as what Alice uploaded.")
		})

		It("should share a file without erroring each append", func() {
			content := []byte("HELLO ITS ME")
			alice.StoreFile(someFilename, content)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			content2 := []byte("012")
			err = bob.AppendToFile(someOtherFilename, content2)
			Expect(err).To(BeNil(), "Bob could not append to the file.")

			content3 := []byte("111")
			err = alice.AppendToFile(someFilename, content3)
			Expect(err).To(BeNil(), "Alice could not append to the file.")

			fcontent := []byte("HELLO ITS ME012111")
			downloadedContent, err := alice.LoadFile(someFilename)
			Expect(err).To(BeNil(), "Alice could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(fcontent),
				"The file contents that Alice downloaded was not the same as what Alice uploaded.")
		})

		It("should share a file without erroring", func() {
			alice.StoreFile(someFilename, someFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")
		})

		It("should share a file without erroring", func() {
			alice.StoreFile(someFilename, someShortFileContent)

			// alice share the file with bob.
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			// bob accept the invitation from alice
			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			// bob tried to accept the invitation twice.
			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).ToNot(BeNil(), "Bob was able to accept twice, which is incorret.")

			// bob tried to accept the invitation of the same file under a different name.
			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, "file3")
			Expect(err).ToNot(BeNil(), "Bob should not accept the same file under the different name.")

			// alice tried to accept the file of her own
			err = alice.AcceptInvitation(aliceUsername, shareFileInfoPtr, someFilename)
			Expect(err).ToNot(BeNil(), "Alice shouldn't accept her own file.")

			err = alice.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).ToNot(BeNil(), "Alice shouldn't accept her own file under the different name")

			err = alice.AcceptInvitation(bobUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).ToNot(BeNil(), "Alice shouldn't accept her own file from bob share")

			// marco tried to accept the invitation when alice share with bob
			err = marco.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).ToNot(BeNil(), "When alice share with bob, marco shouldn't have the invitation.")

			// when bob share with alice
			_, err = bob.CreateInvitation(someOtherFilename, aliceUsername)
			Expect(err).To(BeNil(), "Bob shouldn't share alice's file with alice her own.")

		})
	})

	// 5
	Describe("Revoke files", func() {

		BeforeEach(func() {
			// Initialize each user to ensure the variable has the expected value for
			// the tests in this Describe() block.
			alice, _ = client.InitUser(aliceUsername, alicePassword)
			bob, _ = client.InitUser(bobUsername, bobPassword)
			nilufar, _ = client.InitUser(nilufarUsername, nilufarPassword)
			olga, _ = client.InitUser(olgaUsername, olgaPassword)
			marco, _ = client.InitUser(marcoUsername, marcoPassword)
		})

		// doesn't count
		It("revoke test", func() {
			content := []byte("HELLO ITS ME")
			alice.StoreFile("af", content)
			shareFileInfoPtr, err := alice.CreateInvitation("af", bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, "bf")
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			shareFileInfoPtr2, err := bob.CreateInvitation("bf", olgaUsername)
			Expect(err).To(BeNil(), "Bob failed to share a file with Olga.")

			err = olga.AcceptInvitation(bobUsername, shareFileInfoPtr2, "of")
			Expect(err).To(BeNil(), "Olga could not receive the file that Alice shared.")

			err = alice.RevokeAccess("af", bobUsername)
			Expect(err).To(BeNil(), "Alice could not revoke bob.")

			downloadedContent3, err := alice.LoadFile("af")
			Expect(err).To(BeNil(), "Alice could not load the file that Alice shared.")
			Expect(downloadedContent3).To(BeEquivalentTo(content),
				"The file contents that Alice downloaded was not the same as what Alice uploaded.")

			_, err = bob.LoadFile("bf")
			Expect(err).NotTo(BeNil(), "Bob still can access.")

			_, err = olga.LoadFile("of")
			Expect(err).NotTo(BeNil(), "Olga still can access.")
		})

		// doesn't count
		It("revoke a non-exist user", func() {
			alice.StoreFile(someFilename, someFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			err = alice.RevokeAccess(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice could not revoke bob.")

			err = alice.RevokeAccess(someFilename, nonExistentUsername)
			Expect(err).ToNot(BeNil(), "failed to detect revoke a non-exist username.")
		})
	})

	// 6
	Describe("test non-exist uers and non-exist file", func() {
		BeforeEach(func() {
			// alice, _ = client.InitUser(aliceUsername, alicePassword)
			bob, _ = client.InitUser(bobUsername, bobPassword)
			marco, _ = client.InitUser(marcoUsername, marcoPassword)
		})

		// doesn't count
		It("non-exist uers", func() {

			// exist user share with a non-exist
			err := bob.StoreFile(someFilename, someFileContent)
			Expect(err).To(BeNil(), "bob failed to store file.")

			_, err = bob.CreateInvitation(someFilename, nonExistentUsername)
			Expect(err).ToNot(BeNil(), "bob can't share with DNE user.")

			// non-exist receive from exist
			shareFileInfoPtr, err := bob.CreateInvitation(someFilename, marcoUsername)
			Expect(err).To(BeNil(), "bob failed to share file with marco.")

			err = marco.AcceptInvitation(bobUsername, shareFileInfoPtr, someFilename)
			Expect(err).To(BeNil(), "marco can't receive from bob.")

			err = marco.AcceptInvitation(nonExistentUsername, shareFileInfoPtr, someFilename)
			Expect(err).ToNot(BeNil(), "marco shouldn't receive from non-exist user.")

			err = bob.RevokeAccess(someFilename, nonExistentUsername)
			Expect(err).ToNot(BeNil(), "bob should not revoke from nonExistentUsername.")
		})

		// pass 23
		It("non-exist file", func() {
			alice, _ = client.InitUser(aliceUsername, alicePassword)
			_, err := client.GetUser(aliceUsername, alicePassword)
			Expect(err).To(BeNil(), "failed to get alice.")

			// exist user share with a non-exist
			err = bob.StoreFile(someOtherFilename, someFileContent)
			Expect(err).To(BeNil(), "bob failed to store file.")

			shareFileInfoPtr, err := bob.CreateInvitation(nonExistentFilename, aliceUsername)
			Expect(err).ToNot(BeNil(), "failed to detect bob share a non-exist file with alice.")

			err = alice.AcceptInvitation(bobUsername, shareFileInfoPtr, nonExistentFilename)
			Expect(err).ToNot(BeNil(), "alice can't receive from bob because the file doesn't exist.")

			err = bob.RevokeAccess(nonExistentFilename, aliceUsername)
			Expect(err).ToNot(BeNil(), "bob should not revoke from alice because file doesn't exist.")
		})
	})

	// pass 21
	Describe("test intergity of sharing, loading and appending", func() {
		BeforeEach(func() {
			alice, _ = client.InitUser(aliceUsername, alicePassword)
			bob, _ = client.InitUser(bobUsername, bobPassword)
			marco, _ = client.InitUser(marcoUsername, marcoPassword)
		})

		It("test intergity of loading and appending", func() {
			set := make(map[uuid.UUID]bool)
			dataStoreMap := userlib.DatastoreGetMap()
			for k, _ := range dataStoreMap {
				set[k] = true
			}

			alice.StoreFile(someFilename, someFileContent)
			dataStoreMap = userlib.DatastoreGetMap()

			for k, v := range dataStoreMap {
				if !set[k] {
					dataStoreMap[k] = userlib.RandomBytes(len(v))
					_, err := alice.LoadFile(someFilename)
					alice.AppendToFile(someFilename, userlib.RandomBytes(8))
					Expect(err).ToNot(BeNil(), "failed to check intergrity.") // mark

					userlib.DatastoreDelete(k)
					alice.LoadFile(someFilename)
					// Expect(err).ToNot(BeNil(), "failed to check different.")

					alice.AppendToFile(someFilename, userlib.RandomBytes(8))
					// Expect(err).ToNot(BeNil(), "failed to check intergrity.")

					// reset
					dataStoreMap[k] = v
				}
			}
		})

		// pass 10
		It("test intergity of sharing file", func() {
			alice.StoreFile(someFilename, userlib.RandomBytes(16))

			ptr, _ := alice.CreateInvitation(someFilename, bobUsername)
			dataStoreMap := userlib.DatastoreGetMap()
			magicString := dataStoreMap[ptr]

			for i := 0; i < len(magicString); i++ {
				temp := []byte(string(magicString[:i]) + string(userlib.RandomBytes(1)) + string(magicString[i+1:]))
				dataStoreMap[ptr] = temp
				bob.AcceptInvitation(aliceUsername, ptr, someFilename)
			}
		})

		// pass 16
		It("test intergity of loading file", func() {
			set := make(map[uuid.UUID]bool)
			dataStoreMap := userlib.DatastoreGetMap()
			for k, _ := range dataStoreMap {
				set[k] = true
			}

			alice.StoreFile(someFilename, someFileContent)
			for k, _ := range dataStoreMap {
				if !set[k] {
					temp := dataStoreMap[k]
					dataStoreMap[k] = userlib.RandomBytes(16)
					_, _ = alice.LoadFile(someFilename)
					// Expect(err).ToNot(BeNil(), "failed to load this file.")
					dataStoreMap[k] = temp
				}
			}
		})
	})
})
