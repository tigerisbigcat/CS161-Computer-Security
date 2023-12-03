package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	userlib "github.com/cs161-staff/project2-userlib"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// Useful for string mainpulation.
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.

// This function can be safely deleted!
func someUsefulThings() {
	// Creates a random UUID
	f := userlib.UUIDNew()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Works well with Go structures!
	d, _ := userlib.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g userlib.UUID
	userlib.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// errors.New(...) creates an error type!
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)

	// Useful for string interpolation.
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// HELPER FUNCTIONS
func re(e string) error {
	return errors.New(e)
}

// *********** Symmetric **************
// symmetric enc with padding to 16k
func symEnc(key []byte, content []byte) []byte {
	pad := 16 - len(content) % 16
	for i := 0; i < pad; i++ {
		content = append(content, byte(pad))
	}
	return userlib.SymEnc(key, userlib.RandomBytes(16), content)
}
// symmetric dec with padding to 16k
func symDec(key []byte, content []byte) ([]byte, error) {
	rawText := userlib.SymDec(key, content)
	if len(rawText) % 16 != 0 {
		return nil, re("Invalid padding.")
	}
	pad := int(rawText[len(rawText) - 1])
	if pad > 16 {
		return nil, re("Invalid padding number.")
	}
	for i := len(rawText) - pad; i < len(rawText); i++ {
		if int(rawText[i]) != pad {
			return nil, re("Invalid padding, inconsistent.")
		}
	}
	return rawText[:len(rawText) - pad], nil
}

// *********** HMAC **************
// hmac enc data store Set
func hmacDatastoreSet(id userlib.UUID, content []byte) {
	key := make([]byte, 16)
	for i := range id {
		key[i] = id[i]
	}
	tag, err := userlib.HMACEval(key, content)
	if err != nil {
		return
	}
	userlib.DatastoreSet(id, append(content, tag...))
}
// hmac dec data store Get
func hmacDatastoreGet(id userlib.UUID) ([]byte, bool) {
	key := make([]byte, 16)
	for i := range id {
		key[i] = id[i]
	}
	content, exist := userlib.DatastoreGet(id)
	if !exist {
		return nil, false
	}
	if len(content) < 64 {
		return nil, false
	}
	encData, tag := content[:len(content)-64], content[len(content)-64:]
	nTag, err := userlib.HMACEval(key, encData)
	if err != nil {
		return nil, false
	}
	if !userlib.HMACEqual(tag, nTag) {
		return nil, false
	}
	return encData, true
}
// new a UUID without collision
func newID() userlib.UUID {
	k := userlib.UUIDNew()
	_, ok := hmacDatastoreGet(k)
	for ok {
		k = userlib.UUIDNew()
		_, ok = hmacDatastoreGet(k)
	}
	return k
}

// *********** DS **************
// get the store DS key
func getDSVerify(username string) (userlib.DSVerifyKey, error) {
	key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte("D" + username))[:16]))
	if !ok {
		return key, re(username + " has no DS verify key.")
	}
	return key, nil
}
// DS enc
func dsEnc(dsKey userlib.DSSignKey, content []byte) ([]byte, error) {
	signature, err := userlib.DSSign(dsKey, content)
	if err != nil {
		return nil, re("Fail to sign DS.")
	}
	return append(content, signature...), nil

}
// DS dec
func dsDec(dsKey userlib.DSVerifyKey, id userlib.UUID) ([]byte, error) {
	content, ok := hmacDatastoreGet(id)
	if !ok {
		return nil, re("DNE record in data store.")
	}
	if len(content) < 256 {
		return nil, re("No signature of DS.")
	}
	encData, signature := content[:len(content) - 256], content[len(content) - 256:]
	err := userlib.DSVerify(dsKey, encData, signature)
	return encData, err
}
// facing several ds verification
func verifyDSIntegrity(keys []userlib.DSVerifyKey, id userlib.UUID) ([]byte, error) {
	var encData []byte
	for i := range keys {
		encData, err := dsDec(keys[i], id)
		if err == nil {
			return encData, nil
		}
	}
	return encData, re("None pass.")
}

// get the store PKE key
func getPKEPublic(username string) (userlib.PKEEncKey, error) {
	key, ok := userlib.KeystoreGet(string(userlib.Hash([]byte("P" + username))[:16]))
	if !ok {
		return key, re(username + " has no public PKE key.")
	}
	return key, nil
}

// Deterministic 16 long string
func byte16(s string) []byte {
	a := userlib.Hash([]byte(s))
	return a[len(a)-16:]
}


// User is the structure definition for a user record.
type User struct {
	Username string
	PKey userlib.PKEDecKey
	DKey userlib.DSSignKey
	EncFileNameToFileInfoPtr userlib.UUID
}

// FileInfo
type FileInfo struct {
	Owner string
	ContentUUIDListPtr userlib.UUID
	FileKeyPtr userlib.UUID
	TreeNodePtr userlib.UUID
	TreeNodeKey []byte
}

// Tree Node
type TreeNode struct {
	UsernameToTreeNodePtr map[string]userlib.UUID
	UsernameToTreeNodeKey map[string][]byte
	FileKeyPtr         userlib.UUID // Delete the revoked ones file key directly
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	// Generate a ptr first & check if exist
	userPtr, err := userlib.UUIDFromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(userPtr)
	if ok {
		return nil, re("Username is already taken.")
	}

	// Init username, password
	var userdata User
	userdata.Username = username // Assign

	// InitPkey, Dkey, Generate&Store PKE&DS keys
	var userPKey userlib.PKEEncKey
	userPKey, userdata.PKey, err = userlib.PKEKeyGen() // Assign
	if err != nil {
		return nil, re("Fail generate PKE key.")
	}
	err = userlib.KeystoreSet(string(userlib.Hash([]byte("P" + username))[:16]), userPKey)
	if err != nil {
		return nil, re("Fail store PKE key.")
	}
	var userDKey userlib.DSVerifyKey
	userdata.DKey, userDKey, err = userlib.DSKeyGen() // Assign
	if err != nil {
		return nil, re("Fail generate DS key.")
	}
	err = userlib.KeystoreSet(string(userlib.Hash([]byte("D" + username))[:16]), userDKey)
	if err != nil {
		return nil, re("Fail store DS key.")
	}

	// DEBUG
	_, err = getDSVerify(username)
	if err != nil {
		return nil,  re("WTFFFFFF")
	}

	// Init EncFileNameToFileInfoPtr
	fileInfo := make(map[string]FileInfo, 0)
	marshalFile, err := userlib.Marshal(fileInfo)
	if err != nil {
		return nil, re("Fail marshal file.")
	}
	encFileInfoMap := symEnc(userlib.Hash([]byte(username))[:16], marshalFile) // User username hash to encrypt
	dsEncFileInfoMap, err := dsEnc(userdata.DKey, encFileInfoMap)
	if err != nil {
		return nil, err
	}
	userdata.EncFileNameToFileInfoPtr = newID() // Assign
	hmacDatastoreSet(userdata.EncFileNameToFileInfoPtr, dsEncFileInfoMap)

	// Store user Struct
	// Marshal
	marshalUser, err := userlib.Marshal(userdata)
	if err != nil {
		userlib.DatastoreDelete(userdata.EncFileNameToFileInfoPtr) // Since already failed
		return nil, re("Cannot marshal user struct when init.")
	}
	// Sym Enc
	encUser := symEnc(byte16(username + "USER" + password), marshalUser)
	// DS Enc
	dsEncUser, err:= dsEnc(userdata.DKey, encUser)
	hmacDatastoreSet(userPtr, dsEncUser)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// Generate a ptr first & check if exist
	userPtr, err := userlib.UUIDFromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}

	// DS verify
	userDSVerifyKey, err := getDSVerify(username)
	if err != nil {
		return nil, re(username + " has no DS key.")
	}
	encUser, err := dsDec(userDSVerifyKey, userPtr)
	if err != nil {
		return nil, re("User been modified by unknown.")
	}

	// sym dec
	marshalUser, err := symDec(byte16(username + "USER" + password), encUser)
	if err != nil {
		return nil, err
	}

	// unmarshal
	var userdata User
	err = userlib.Unmarshal(marshalUser, &userdata)
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}

func getFileMap(id userlib.UUID, username string) (map[string]FileInfo, userlib.DSVerifyKey, error) {
	// Get key
	verifyDKey, err := getDSVerify(username)
	if err != nil {
		return nil, verifyDKey, err
	}
	// ds dec
	encFile, err := dsDec(verifyDKey, id)
	if err != nil {
		return nil, verifyDKey, err
	}
	// sym dec
	marshalFile, err := symDec(userlib.Hash([]byte(username))[:16], encFile)
	if err != nil {
		return nil, verifyDKey, err
	}
	// New a string:FileInfo struct
	var fileInfoMap map[string]FileInfo
	err = userlib.Unmarshal(marshalFile, &fileInfoMap)
	if err != nil {
		return nil, verifyDKey, err
	}
	return fileInfoMap, verifyDKey, nil
}
func getFileInfo(filename string, fileInfoMap map[string]FileInfo) (FileInfo, bool) {
	var fileInfo FileInfo
	hashedFilename := hex.EncodeToString(userlib.Hash([]byte(filename)))
	fileInfo, ok := fileInfoMap[hashedFilename]
	return fileInfo, ok
}
func getFileKey(dsKeys []userlib.DSVerifyKey, pkeKey userlib.PKEDecKey, id userlib.UUID) ([]byte, error) {
	encFileKey, err := verifyDSIntegrity(dsKeys, id)
	if err != nil {
		return nil, err
	}
	fileKey, err := userlib.PKEDec(pkeKey, encFileKey)
	if err != nil {
		return nil, err
	}
	return fileKey, nil
}
func getEncDS(keys []userlib.DSVerifyKey, id userlib.UUID) ([]byte, error) {
	var encData []byte
	for i := range keys {
		encData, err := dsDec(keys[i], id)
		if err == nil {
			return encData, nil
		}
	}
	return encData, re("None pass.")
}
func getEncContentList(fileKey []byte, id userlib.UUID, delete bool) ([][]byte, []userlib.UUID, error) {
	contentEncList, ok := hmacDatastoreGet(id)
	if !ok {
		return nil, nil, re("No record for the content.")
	}
	marshalContentList, err := symDec(fileKey, contentEncList)
	if err != nil {
		return nil, nil, err
	}
	var idList []userlib.UUID
	err = userlib.Unmarshal(marshalContentList, &idList)
	var encContentList [][]byte
	for i:= 0; i < len(idList); i++ {
		encContent, ok := hmacDatastoreGet(idList[i])
		if !ok {
			return nil, nil, re("Content been modified.")
		}
		encContentList = append(encContentList, encContent)
		if delete {
			userlib.DatastoreDelete(idList[i])
		}
	}
	return encContentList, idList, nil
}
func addFileInfo(filename string, fileInfoMap map[string]FileInfo, fileInfo FileInfo) (map[string]FileInfo, error) {
	hashedFilename := hex.EncodeToString(userlib.Hash([]byte(filename)))
	_, ok := fileInfoMap[hashedFilename]
	if ok {
		return nil, re("Exist such file.")
	}
	fileInfoMap[hashedFilename] = fileInfo
	return fileInfoMap, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// Get the fileInfoMap First
	fileInfoMap, userVDKey, err := getFileMap(userdata.EncFileNameToFileInfoPtr, userdata.Username)
	if err != nil {
		return err
	}

	// Check if user have the file
	fileInfo, exist := getFileInfo(filename, fileInfoMap)

	if exist {
		// This file can be accessed by me and the owner
		ownerVDKey, err := getDSVerify(fileInfo.Owner)
		if err != nil {
			return err
		}
		dsKeys := []userlib.DSVerifyKey{ownerVDKey, userVDKey}

		// Get the filekey for later encryption
		fileKey, err := getFileKey(dsKeys, userdata.PKey, fileInfo.FileKeyPtr)
		if err != nil {
			return err
		}

		// verify old data see if anyone damage it
		_, err = getEncDS(dsKeys, fileInfo.TreeNodePtr) // treenode
		if err != nil {
			return err
		}
		_, _, err = getEncContentList(fileKey, fileInfo.ContentUUIDListPtr, true) // prev content
		if err != nil {
			return err
		}

		// Encrypt current content
		encContent := symEnc(fileKey, content)
		contentPtr := newID()
		hmacDatastoreSet(contentPtr, encContent)

		// Update the idList
		newIdList := []userlib.UUID{contentPtr}
		marshalNewIdList, err := userlib.Marshal(newIdList)
		if err != nil {
			return err
		}
		encNewIdList := symEnc(fileKey, marshalNewIdList)
		hmacDatastoreSet(fileInfo.ContentUUIDListPtr, encNewIdList)
	} else {
		// Create a new file info
		var newFileInfo FileInfo

		// New a file key and store by self pke ds key enc
		fileKey := userlib.RandomBytes(16)
		pPKey, err := getPKEPublic(userdata.Username)
		if err != nil {
			return re(userdata.Username + " has no PKE pub key.")
		}
		encFileKey, err := userlib.PKEEnc(pPKey, fileKey)
		if err != nil{
			return err
		}
		dsEncFileKey, err := dsEnc(userdata.DKey, encFileKey)
		if err != nil{
			return err
		}
		newFileInfo.FileKeyPtr = newID() // Assign
		hmacDatastoreSet(newFileInfo.FileKeyPtr, dsEncFileKey)

		// Sym Enc content by file key
		encContent := symEnc(fileKey, content)
		encContentPtr := newID()
		hmacDatastoreSet(encContentPtr, encContent)

		// Content id list enc and store
		idList := []userlib.UUID{encContentPtr}
		marshalIdList, err := userlib.Marshal(idList)
		if err != nil {
			return err
		}
		encIdList := symEnc(fileKey, marshalIdList)
		newFileInfo.ContentUUIDListPtr = newID() // Assign
		hmacDatastoreSet(newFileInfo.ContentUUIDListPtr, encIdList)

		// Owner is user
		newFileInfo.Owner = userdata.Username // Assign

		// TreeNode
		newFileInfo.TreeNodeKey = userlib.RandomBytes(16) // Assign

		var treeNode TreeNode
		treeNode.UsernameToTreeNodeKey = make(map[string][]byte)
		treeNode.UsernameToTreeNodePtr = make(map[string]userlib.UUID)
		treeNode.FileKeyPtr = newFileInfo.FileKeyPtr
		marshalTreeNode, err := userlib.Marshal(treeNode)
		if err != nil {
			return err
		}
		encTreeNode := symEnc(newFileInfo.TreeNodeKey, marshalTreeNode)
		dsEncTreeNode, err := dsEnc(userdata.DKey, encTreeNode)
		if err != nil {
			return err
		}
		newFileInfo.TreeNodePtr = newID()
		hmacDatastoreSet(newFileInfo.TreeNodePtr, dsEncTreeNode)

		// Add new file info to the map
		newFileInfoMap, err := addFileInfo(filename, fileInfoMap, newFileInfo)
		if err != nil {
			return err
		}
		marshalNewFileInfoMap, err := userlib.Marshal(newFileInfoMap)
		if err != nil {
			return err
		}
		encNewFileInfoMap := symEnc(userlib.Hash([]byte(userdata.Username))[:16], marshalNewFileInfoMap)
		dsEncNewFileInfoMap, err := dsEnc(userdata.DKey, encNewFileInfoMap)
		if err != nil {
			return err
		}
		hmacDatastoreSet(userdata.EncFileNameToFileInfoPtr, dsEncNewFileInfoMap)
	}
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// Get the fileInfoMap First
	fileInfoMap, userVDKey, err := getFileMap(userdata.EncFileNameToFileInfoPtr, userdata.Username)
	if err != nil {
		return err
	}

	// Check if user have the file
	fileInfo, exist := getFileInfo(filename, fileInfoMap)
	if !exist {
		return re("DNE file so cannot append.")
	}

	// This file can be accessed by me and the owner
	ownerVDKey, err := getDSVerify(fileInfo.Owner)
	if err != nil {
		return err
	}
	dsKeys := []userlib.DSVerifyKey{ownerVDKey, userVDKey}

	// Get the file key for later encryption
	fileKey, err := getFileKey(dsKeys, userdata.PKey, fileInfo.FileKeyPtr)
	if err != nil {
		return err
	}

	// verify old data see if anyone damage it
	_, err = getEncDS(dsKeys, fileInfo.TreeNodePtr) // treenode
	if err != nil {
		return err
	}
	_,_, err = getEncContentList(fileKey, fileInfo.ContentUUIDListPtr, false) // prev content
	if err != nil {
		return err
	}

	// Get the content list uuid list
	encIdList, ok := hmacDatastoreGet(fileInfo.ContentUUIDListPtr)
	if !ok {
		return re("No content list data.")
	}
	marshalIdList, err := symDec(fileKey, encIdList)
	var idList []userlib.UUID
	err = userlib.Unmarshal(marshalIdList, &idList)
	if err != nil {
		return err
	}

	// Append the newest one to the end of the list
	idList = append(idList, newID())

	// Encrypt the content
	encContent := symEnc(fileKey, content)
	hmacDatastoreSet(idList[len(idList)-1], encContent)

	// Store new idList
	marshalIdList, err = userlib.Marshal(idList)
	if err != nil {
		return err
	}
	encIdList = symEnc(fileKey, marshalIdList)
	hmacDatastoreSet(fileInfo.ContentUUIDListPtr, encIdList)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// Get the fileInfoMap First
	fileInfoMap, userVDKey, err := getFileMap(userdata.EncFileNameToFileInfoPtr, userdata.Username)
	if err != nil {
		return nil, err
	}

	// Check if user have the file
	fileInfo, exist := getFileInfo(filename, fileInfoMap)
	if !exist {
		return nil, re("DNE file.")
	}

	// This file can be accessed by me and the owner
	ownerVDKey, err := getDSVerify(fileInfo.Owner)
	if err != nil {
		return nil, err
	}
	dsKeys := []userlib.DSVerifyKey{ownerVDKey, userVDKey}

	// Get the file key for later encryption
	fileKey, err := getFileKey(dsKeys, userdata.PKey, fileInfo.FileKeyPtr)
	if err != nil {
		return nil, err
	}

	// verify old data tree node see if anyone damage it
	_, err = getEncDS(dsKeys, fileInfo.TreeNodePtr) // treenode
	if err != nil {
		return nil, err
	}
	encContentList, _, err := getEncContentList(fileKey, fileInfo.ContentUUIDListPtr, false) // prev content
	if err != nil {
		return nil, err
	}

	fContent := []byte{}
	for i := 0; i < len(encContentList); i++ {
		rawContent, err := symDec(fileKey, encContentList[i])
		if err != nil {
			return nil, err
		}
		fContent = append(fContent, rawContent...)
	}
	return fContent, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr userlib.UUID, err error) {
	invitationPtr = newID()
	// Get the fileInfoMap First
	fileInfoMap, userVDKey, err := getFileMap(userdata.EncFileNameToFileInfoPtr, userdata.Username)
	if err != nil {
		return invitationPtr, re("1")
	}

	// Check if user have the file
	fileInfo, exist := getFileInfo(filename, fileInfoMap)
	if !exist {
		return invitationPtr, re("DNE file.2")
	}

	// Get the file key
	ownerVDKey, err := getDSVerify(fileInfo.Owner)
	if err != nil {
		return invitationPtr, re("3")
	}
	dsKeys := []userlib.DSVerifyKey{ownerVDKey, userVDKey}
	fileKey, err := getFileKey(dsKeys, userdata.PKey, fileInfo.FileKeyPtr)
	if err != nil {
		return invitationPtr, re("4")
	}

	// verify old data see if anyone damage it
	encTreeNode, err := getEncDS(dsKeys, fileInfo.TreeNodePtr) // treenode
	if err != nil {
		return invitationPtr, re("5")
	}
	_,_, err = getEncContentList(fileKey, fileInfo.ContentUUIDListPtr, false) // prev content
	if err != nil {
		return invitationPtr, re("6")
	}

	// Check if the recipient already accessible
	marshalTreeNode, err := symDec(fileInfo.TreeNodeKey, encTreeNode)
	if err != nil {
		return invitationPtr, re("7")
	}
	var treeNodeHost TreeNode
	err = userlib.Unmarshal(marshalTreeNode, &treeNodeHost)
	if len(treeNodeHost.UsernameToTreeNodePtr) != len(treeNodeHost.UsernameToTreeNodeKey) {
		return invitationPtr, re("The inheritance relation is messed up.8")
	}
	_, exist = treeNodeHost.UsernameToTreeNodePtr[recipientUsername]
	if exist {
		return invitationPtr, re(recipientUsername + "Already accessible.9")
	}
	_, exist = treeNodeHost.UsernameToTreeNodeKey[recipientUsername]
	if exist {
		return invitationPtr, re("The inheritance relation is messed up since some keymap ptrmap have difference keys.10")
	}

	// New a fileInfo struct for the recipient
	var newFileInfo FileInfo
	newFileInfo.ContentUUIDListPtr = fileInfo.ContentUUIDListPtr // Assign
	newFileInfo.Owner = fileInfo.Owner // Assign
	newFileInfo.FileKeyPtr = newID() // Assign
	newFileInfo.TreeNodePtr = newID() // Assign
	newFileInfo.TreeNodeKey = userlib.RandomBytes(16) // Assign

	// Complete the file info abstract struct (including thing it points to)
	// filekey
	recipientPKey, err := getPKEPublic(recipientUsername)
	if err != nil {
		return invitationPtr, re("11No public PKE key for " + recipientUsername)
	}
	encNewFileKey, err := userlib.PKEEnc(recipientPKey, fileKey)
	if err != nil {
		return invitationPtr, re("12New file key PKE Encryption failed.")
	}
	dsEncNewFileKey, err := dsEnc(userdata.DKey, encNewFileKey)
	if err != nil {
		return invitationPtr, re("13New file key DS Encryption failed.")
	}
	hmacDatastoreSet(newFileInfo.FileKeyPtr, dsEncNewFileKey)
	// treenode
	var newTreeNode TreeNode
	newTreeNode.UsernameToTreeNodePtr = make(map[string]userlib.UUID)
	newTreeNode.UsernameToTreeNodeKey = make(map[string][]byte)
	newTreeNode.FileKeyPtr = newFileInfo.FileKeyPtr
	marshalNewTreeNode, err := userlib.Marshal(newTreeNode)
	if err != nil {
		return invitationPtr, re("14")
	}
	encNewTreeNode := symEnc(newFileInfo.TreeNodeKey, marshalNewTreeNode)
	dsEncNewTreeNode, err := dsEnc(userdata.DKey, encNewTreeNode)
	if err != nil {
		return invitationPtr, re("15")
	}
	hmacDatastoreSet(newFileInfo.TreeNodePtr, dsEncNewTreeNode)

	treeNodeHost.UsernameToTreeNodeKey[recipientUsername] = newFileInfo.TreeNodeKey
	treeNodeHost.UsernameToTreeNodePtr[recipientUsername] = newFileInfo.TreeNodePtr
	marshalTreeNodeHost, err := userlib.Marshal(treeNodeHost)
	if err != nil {
		return invitationPtr, re("16")
	}
	encTreeNodeHost := symEnc(fileInfo.TreeNodeKey, marshalTreeNodeHost)
	dsEncTreeNodeHost, err := dsEnc(userdata.DKey, encTreeNodeHost)
	if err != nil {
		return invitationPtr, re("17")
	}
	hmacDatastoreSet(fileInfo.TreeNodePtr, dsEncTreeNodeHost)

	// Store new File info struct
	keyForNewFileInfo := userlib.RandomBytes(16)
	marshalNewFileInfo, err := userlib.Marshal(newFileInfo)
	if err != nil {
		return invitationPtr, re("18")
	}
	encNewFileInfo := symEnc(keyForNewFileInfo, marshalNewFileInfo)
	dsEncNewFileInfo, err := dsEnc(userdata.DKey, encNewFileInfo)
	uuidForNewFileInfo := newID()
	hmacDatastoreSet(uuidForNewFileInfo, dsEncNewFileInfo)

	// Generate the invitation ptr record
	byteUUIdForNewFileInfo := make([]byte, 16)
	for i := 0; i < 16; i++ {
		byteUUIdForNewFileInfo[i] = uuidForNewFileInfo[i]
	}
	inviContent := append(byteUUIdForNewFileInfo, keyForNewFileInfo...)
	pkeEncInviContent, err := userlib.PKEEnc(recipientPKey, inviContent)
	if err != nil {
		return invitationPtr, re("19")
	}
	dsPKEEncInviContent, err := dsEnc(userdata.DKey, pkeEncInviContent)
	if err != nil {
		return invitationPtr, re("20")
	}

	// Store the invitation info
	hmacDatastoreSet(invitationPtr, dsPKEEncInviContent)

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr userlib.UUID, filename string) error {
	// Sender VDKey
	senderVDKey, err := getDSVerify(senderUsername)
	if err != nil {
		return re("1")
	}

	// If exist such invitation, if so ds dec
	pkeEncInviConent, err := dsDec(senderVDKey, invitationPtr)
	if err != nil {
		return re("2The invitation DNE.")
	}

	// Delete the invitation ptr since we got its content
	userlib.DatastoreDelete(invitationPtr)

	// PKE dec invitation
	inviContent, err := userlib.PKEDec(userdata.PKey, pkeEncInviConent)
	if len(inviContent) != 32 {
		return re("3")
	}

	// Bytes uuid & symkey for fileinfo
	var inviFileInfoPtr userlib.UUID
	for i := 0; i < 16; i++ {
		inviFileInfoPtr[i] = inviContent[i]
	}
	inviFileInfoKey := inviContent[16:32]

	// Get the inviFileInfo
	encInviFileInfo, err := dsDec(senderVDKey, inviFileInfoPtr)
	if err != nil {
		return re("4")
	}
	marshalInvifileInfo, err  := symDec(inviFileInfoKey, encInviFileInfo)
	if err != nil {
		return re("5")
	}
	var inviFileInfo FileInfo
	err = userlib.Unmarshal(marshalInvifileInfo, &inviFileInfo)
	if err != nil {
		return re("6")
	}

	// Delete invitation File info record
	userlib.DatastoreDelete(inviFileInfoPtr)

	// For later DS verify usage
	ownerVDKey, err := getDSVerify(inviFileInfo.Owner)
	if err != nil {
		return re("7")
	}
	dsKeys := []userlib.DSVerifyKey{ownerVDKey, senderVDKey}

	// Check FileKey and DS resign
	fileKey, err := getFileKey(dsKeys, userdata.PKey, inviFileInfo.FileKeyPtr)
	if len(fileKey) != 16 {
		return re("8")
	}
	pkeEncFileKey, err := verifyDSIntegrity(dsKeys, inviFileInfo.FileKeyPtr)
	if err != nil {
		return re("9")
	}
	dsEncFileKey, err := dsEnc(userdata.DKey, pkeEncFileKey)
	if err != nil {
		return re("10")
	}
	hmacDatastoreSet(inviFileInfo.FileKeyPtr, dsEncFileKey)

	// Check tree node and Ds resign
	encInviTreeNode, err := getEncDS(dsKeys, inviFileInfo.TreeNodePtr)
	if err != nil {
		return re("11")
	}
	marInviTreeNode, err := symDec(inviFileInfo.TreeNodeKey, encInviTreeNode)
	if err != nil {
		return re("12")
	}
	var inviTreeNode TreeNode
	err = userlib.Unmarshal(marInviTreeNode, &inviTreeNode)
	if err != nil {
		return re("13")
	}
	if inviTreeNode.UsernameToTreeNodePtr == nil || inviTreeNode.UsernameToTreeNodeKey == nil {
		return re("14")
	}
	inviTreeNode.FileKeyPtr = inviFileInfo.FileKeyPtr
	marInviTreeNode, err = userlib.Marshal(inviTreeNode)
	if err != nil {
		return re("14")
	}
	encInviTreeNode = symEnc(inviFileInfo.TreeNodeKey, marInviTreeNode)
	dsEncInviTreeNode, err := dsEnc(userdata.DKey, encInviTreeNode)
	if err != nil {
		return re("15")
	}
	hmacDatastoreSet(inviFileInfo.TreeNodePtr, dsEncInviTreeNode)

	// Add the new fileInfo back to user fileMap
	// Get the fileInfoMap First
	fileInfoMap, _, err := getFileMap(userdata.EncFileNameToFileInfoPtr, userdata.Username)
	if err != nil {
		return re("16")
	}

	// Check if user have the file
	_, exist := getFileInfo(filename, fileInfoMap)
	if exist {
		return re("17The user has the file, cannot accept the invitation again.")
	}

	// add this new file info to the user data
	newFileInfoMap, err := addFileInfo(filename, fileInfoMap, inviFileInfo)
	if err != nil {
		return re("18")
	}
	marshalNewFileInfoMap, err := userlib.Marshal(newFileInfoMap)
	if err != nil {
		return re("19")
	}
	encNewFileInfoMap := symEnc(userlib.Hash([]byte(userdata.Username))[:16], marshalNewFileInfoMap)
	dsEncNewFileInfoMap, err := dsEnc(userdata.DKey, encNewFileInfoMap)
	if err != nil {
		return re("20")
	}
	hmacDatastoreSet(userdata.EncFileNameToFileInfoPtr, dsEncNewFileInfoMap)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//// Check self if is the owner of the file
	// Get the fileInfoMap First
	fileInfoMap, ownerVDKey, err := getFileMap(userdata.EncFileNameToFileInfoPtr, userdata.Username) // The verify key will be used iif the user is the owner
	if err != nil {
		return re("0")
	}

	// Check if user have the file
	fileInfo, exist := getFileInfo(filename, fileInfoMap)
	if !exist {
		return re("1You don't have the file.")
	}

	// If not the owner return
	if fileInfo.Owner != userdata.Username {
		return re("2 Only fil owner can revoke.")
	}
	dsKeys := []userlib.DSVerifyKey{ownerVDKey}

	//// Expand the Tree Node & verify if the recipient in my tree node
	// Expand the tree node
	encInviTreeNode, err := getEncDS(dsKeys, fileInfo.TreeNodePtr)
	if err != nil {
		return re("3")
	}
	marInviTreeNode, err := symDec(fileInfo.TreeNodeKey, encInviTreeNode)
	if err != nil {
		return re("4")
	}
	var inviTreeNode TreeNode
	err = userlib.Unmarshal(marInviTreeNode, &inviTreeNode)
	if err != nil {
		return re("5")
	}

	// Verify if the username in it
	if len(inviTreeNode.UsernameToTreeNodeKey) != len(inviTreeNode.UsernameToTreeNodePtr) {
		return re("6 Inheritance relation messed up.")
	}
	recipientTreeNodeKey, ok1 := inviTreeNode.UsernameToTreeNodeKey[recipientUsername]
	recipientTreeNodePtr, ok2 := inviTreeNode.UsernameToTreeNodePtr[recipientUsername]
	if !ok1 || !ok2 {
		return re("7 Inheritance relation messed up.")
	}
	delete(inviTreeNode.UsernameToTreeNodeKey, recipientUsername) // Delete this guy
	delete(inviTreeNode.UsernameToTreeNodePtr, recipientUsername) // Delete this guy

	//// BFS over this recipient and delete all their relevant information
	usernameQueue := []string{recipientUsername}
	treeNodePtrQueue := []userlib.UUID{recipientTreeNodePtr}
	treeNodeKeyQueue := [][]byte{recipientTreeNodeKey}
	userParentNameQueue := []string{userdata.Username}
	for len(usernameQueue) > 0 {
		// Get current info
		curUsername := usernameQueue[0]
		curTreeNodePtr := treeNodePtrQueue[0]
		curTreeNodeKey := treeNodeKeyQueue[0]
		curUserParentName := userParentNameQueue[0]

		// Update the queue
		usernameQueue = usernameQueue[1:]
		treeNodePtrQueue = treeNodePtrQueue[1:]
		treeNodeKeyQueue = treeNodeKeyQueue[1:]
		userParentNameQueue = userParentNameQueue[1:]

		// Get ds keys for encrytion
		curUserVDKey, err := getDSVerify(curUsername)
		if err != nil {
			return re("1B0")
		}
		parentVDKey, err := getDSVerify(curUserParentName)
		if err != nil {
			return re("1B1")
		}
		dsKeys := []userlib.DSVerifyKey{ownerVDKey, curUserVDKey, parentVDKey}

		// Get the encrypted tree node
		encTreeNode, err := getEncDS(dsKeys, curTreeNodePtr)
		if err != nil {
			return re("1B2")
		}
		curMarTreeNode, err := symDec(curTreeNodeKey, encTreeNode)
		if err != nil {
			return re("1B3")
		}
		var curTreeNode TreeNode
		err = userlib.Unmarshal(curMarTreeNode, &curTreeNode)
		if err != nil {
			return re("1B4")
		}

		// Delete the tree node record in the data store
		userlib.DatastoreDelete(curTreeNodePtr)

		// Verify current TreeNode
		if curTreeNode.UsernameToTreeNodePtr == nil || curTreeNode.UsernameToTreeNodeKey == nil {
			return re("Inheritance messed up (nil) when do BFS checking to be revoked.")
		}
		if len(curTreeNode.UsernameToTreeNodePtr) != len(curTreeNode.UsernameToTreeNodeKey) {
			return re("Inheritance messed up (length not same) when do BFS checking to be revoked.")
		}
		for childName, childrenNodePtr := range curTreeNode.UsernameToTreeNodePtr {
			childrenNodekey, exist := curTreeNode.UsernameToTreeNodeKey[childName]
			if !exist {
				return re("Inheritance messed up (non-match keys) when do BFS checking to be revoked.")
			}
			usernameQueue = append(usernameQueue, childName)
			treeNodePtrQueue = append(treeNodePtrQueue, childrenNodePtr)
			treeNodeKeyQueue = append(treeNodeKeyQueue, childrenNodekey)
			userParentNameQueue = append(userParentNameQueue, curUsername)
		}

		// Delete corresponding file key
		userlib.DatastoreDelete(curTreeNode.FileKeyPtr)
	}

	//// Update the file content and its ID LIST
	// Get original fileKey
	fileKey, err := getFileKey(dsKeys, userdata.PKey, fileInfo.FileKeyPtr)
	if err != nil {
		return re("7.5")
	}

	// Get idList & Content List
	fileContentList, idList, err := getEncContentList(fileKey, fileInfo.ContentUUIDListPtr, false)
	if err != nil {
		return re("8")
	}

	// New a file key and update owner
	newFileKey := userlib.RandomBytes(16)

	// Re enc idList
	newMarIDList, err := userlib.Marshal(idList)
	if err != nil {
		return re("9")
	}
	newEncIDList := symEnc(newFileKey, newMarIDList)
	hmacDatastoreSet(fileInfo.ContentUUIDListPtr, newEncIDList)

	// Re enc contentList
	if len(idList) != len(fileContentList) {
		return re("10")
	}
	for i := 0; i < len(fileContentList); i++ {
		curEncContent := fileContentList[i]
		curContent, err := symDec(fileKey, curEncContent)
		if err != nil {
			return re("10.5")
		}
		encCurContent := symEnc(newFileKey, curContent)
		hmacDatastoreSet(idList[i], encCurContent)
	}

	ownerPKEKey, err := getPKEPublic(userdata.Username)
	if err != nil {
		return re("1.5B0")
	}
	pkeEncNewFileKey, err := userlib.PKEEnc(ownerPKEKey, newFileKey)
	if err != nil {
		return re("1.5B1")
	}
	dsPKEEncNewFileKey, err := dsEnc(userdata.DKey, pkeEncNewFileKey)
	if err != nil {
		return re("1.5B1")
	}
	hmacDatastoreSet(inviTreeNode.FileKeyPtr, dsPKEEncNewFileKey)
	//hmacDatastoreSet(fileInfo.FileKeyPtr, dsPKEEncNewFileKey)

	//// BFS over myself and update all their information
	// New a BFS for everyone else to update
	usernameQueue = []string{}
	treeNodePtrQueue = []userlib.UUID{}
	treeNodeKeyQueue = [][]byte{}
	userParentNameQueue = []string{}
	for childName, childrenNodePtr := range inviTreeNode.UsernameToTreeNodePtr {
		childrenNodeKey, exist := inviTreeNode.UsernameToTreeNodeKey[childName]
		if !exist {
			return re("1.5B2 Inheritance messed up (non-match keys) when do BFS checking to be revoked.")
		}
		usernameQueue = append(usernameQueue, childName)
		treeNodePtrQueue = append(treeNodePtrQueue, childrenNodePtr)
		treeNodeKeyQueue = append(treeNodeKeyQueue, childrenNodeKey)
		userParentNameQueue = append(userParentNameQueue, userdata.Username)
	}
	for len(usernameQueue) > 0 {
		// Get current info
		curUsername := usernameQueue[0]
		curTreeNodePtr := treeNodePtrQueue[0]
		curTreeNodeKey := treeNodeKeyQueue[0]
		curUserParentName := userParentNameQueue[0]

		// Update the queue
		usernameQueue = usernameQueue[1:]
		treeNodePtrQueue = treeNodePtrQueue[1:]
		treeNodeKeyQueue = treeNodeKeyQueue[1:]
		userParentNameQueue = userParentNameQueue[1:]

		// Get ds keys for encrytion
		curUserVDKey, err := getDSVerify(curUsername)
		if err != nil {
			return re("2B0")
		}
		parentVDKey, err := getDSVerify(curUserParentName)
		if err != nil {
			return re("2B1")
		}
		curDsKeys := []userlib.DSVerifyKey{ownerVDKey, curUserVDKey, parentVDKey}

		// Get the encrypted tree node
		encTreeNode, err := getEncDS(curDsKeys, curTreeNodePtr)
		if err != nil {
			return re("2B2")
		}
		curMarTreeNode, err := symDec(curTreeNodeKey, encTreeNode)
		if err != nil {
			return re("2B3")
		}
		var curTreeNode TreeNode
		err = userlib.Unmarshal(curMarTreeNode, &curTreeNode)
		if err != nil {
			return re("2B4")
		}

		// Verify current TreeNode
		if curTreeNode.UsernameToTreeNodePtr == nil || curTreeNode.UsernameToTreeNodeKey == nil {
			return re("Inheritance messed up (nil) when do BFS checking to be revoked.")
		}
		if len(curTreeNode.UsernameToTreeNodePtr) != len(curTreeNode.UsernameToTreeNodeKey) {
			return re("Inheritance messed up (length not same) when do BFS checking to be revoked.")
		}
		for childName, childrenNodePtr := range curTreeNode.UsernameToTreeNodePtr {
			childrenNodeKey, exist := curTreeNode.UsernameToTreeNodeKey[childName]
			if !exist {
				return re("Inheritance messed up (non-match keys) when do BFS checking to be revoked.")
			}
			usernameQueue = append(usernameQueue, childName)
			treeNodePtrQueue = append(treeNodePtrQueue, childrenNodePtr)
			treeNodeKeyQueue = append(treeNodeKeyQueue, childrenNodeKey)
			userParentNameQueue = append(userParentNameQueue, curUsername)
		}

		// Update corresponding file key
		curUserPKEKey, err := getPKEPublic(curUsername)
		if err != nil {
			return re(curUsername + " has no PKE public key!")
		}
		pkeEncFileKey, err := userlib.PKEEnc(curUserPKEKey, newFileKey)
		dsPKEEncFileKey, err := dsEnc(userdata.DKey, pkeEncFileKey)
		hmacDatastoreSet(curTreeNode.FileKeyPtr, dsPKEEncFileKey)
	}

	return nil
}
