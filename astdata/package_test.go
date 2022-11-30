package astdata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/emirpasic/gods/sets/hashset"
	"io/ioutil"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackage(t *testing.T) {
	p, err := ParsePackage("fixture")
	require.NoError(t, err)
	assert.Equal(t, p.Path(), "fixture")
	assert.Equal(t, p.Name(), "fixture")

	_, err = translateToFullPath("invalid_path")
	assert.Error(t, err)
	_, err = translateToFullPath("not/exists/package")
	assert.Error(t, err)

	p = &Package{}

	f1, err := ParseFile(testArrr, p)
	require.NoError(t, err)
	f2, err := ParseFile(testFunc, p)
	require.NoError(t, err)
	f3, err := ParseFile(testImport, p)
	require.NoError(t, err)
	f4, err := ParseFile(testConst, p)
	require.NoError(t, err)

	p.files = append(p.files, f1, f2, f3, f4)

	assert.Len(t, p.Files(), 4)
	assert.NotEmpty(t, p.Functions())
	assert.NotEmpty(t, p.Variables())
	assert.NotEmpty(t, p.Types())
	assert.NotEmpty(t, p.Imports())
	assert.NotEmpty(t, p.Constants())
}

type CodeGenConf struct {
	genTplFile          bool
	genProxyWMSAPICode  bool
	genSrcProxyCodeFile bool
}

func TestWMSV2(t *testing.T) {
	packageMap := map[string]*Package{}
	name := "apps/config/manager/msizetype"
	codeBase := "/Users/yunfeizhu/Code/golang/wms-v2/apps/wmslib/wmsbasic"
	srcBase := "/Users/yunfeizhu/Code/golang/wms-v2/apps/config/manager/msizetype"
	pbBase := "/Users/yunfeizhu/Code/golang/wms-protobuf/apps/basic/pbnewbasic"
	pbSrcBase := "apps/basic/pbnewbasic/pbmsizetype"

	genConf := &CodeGenConf{
		genTplFile:          false,
		genProxyWMSAPICode:  true,
		genSrcProxyCodeFile: false,
	}

	err := ParsePackage2(packageMap, name, true)
	if err != nil {
		t.Error(err.Error())
	}
	p := packageMap[name]
	pcode := parsePCode(p)

	err = parsePbStructs(pbSrcBase, pcode, packageMap)
	if err != nil {
		t.Error(err.Error())
	}

	//tpl
	if genConf.genTplFile {
		err = genProxyAPIPbTpl(pbBase, pcode, packageMap)
		if err != nil {
			t.Error(err.Error())
		}
		extLines := []string{"message MapItem{\n  optional string m_key = 1;\n  optional string m_value = 2;\n  optional string m_type = 3;\n}\nmessage PageInItem{\n  optional  int64  Pageno = 1;       //页码\n  optional  int64     count = 2 ;    // 数量\n  optional  string  order_by = 3;    // 为空字符串 代表不需要排序\n  optional  bool  is_get_total = 4;  // 为False代表不需要获取总数\n}"}

		pcode.ouStructTplDbsMaps["entity"] = append(pcode.ouStructTplDbsMaps["entity"], extLines...)

		err = genTplFile(pbBase, pcode)
		if err != nil {
			t.Error(err.Error())
		}
	}

	if genConf.genProxyWMSAPICode {
		//wmsbasic api
		pbPkg := packageMap[pbSrcBase]
		err = genProxyAPICodeFile(codeBase, pbPkg, pcode)
		if err != nil {
			t.Error(err.Error())
		}
	}
	if genConf.genSrcProxyCodeFile {
		err = genSrcProxyCodeFile(srcBase, pcode)
		if err != nil {
			t.Error(err.Error())
		}
	}
	//genWMSV2ProxyPB(p)
	//genWMSV2ProxyAPI(p)
	//genWMSV2ProxyTestAPI(p)
	//genBasicAPI(p)

}

func parsePbStructs(pbSrcBase string, pcode *PCode, packageMap map[string]*Package) error {

	//module := pcode.p.name
	//pkgPbDir := "pb" + module
	////tpl := base + "/" + pkgPbDir
	////tplCommon := base + "/pbcommon"
	//pkgBase := "git.garena.com/shopee/bg-logistics/tianlu/wms-protobuf/apps/basic/pbnewbasic"
	//importPkgBase := "apps/basic/pbnewbasic"
	//goPkgPath := fmt.Sprintf("%s/%s", pkgBase, pkgPbDir)
	//importDtoPkg := fmt.Sprintf("%s/%s/%s_dto.tpl.proto", importPkgBase, pkgPbDir, module)
	//importCommonPkg := fmt.Sprintf("%s/%s/entity_entity.tpl.proto", importPkgBase, pkgPbDir)

	err := ParsePbPackage2(packageMap, pbSrcBase)
	if err != nil {
		return err
	}
	return nil
}

func genProxyAPICodeFile(base string, pbSrcPkg *Package, pcode *PCode) error {
	filePre := base + "/" + pcode.p.name

	packageHead := "package wmsbasic"
	apiFiles := []string{packageHead}
	var basicAPISign []string
	for _, sign := range pcode.basicAPIDefMap {
		basicAPISign = append(basicAPISign, sign)
	}
	apiFiles = append(apiFiles, buildPackageProxyBasicAPI(pcode.p, basicAPISign)...)
	err := ioutil.WriteFile(filePre+"_basic_api.go", []byte(strings.Join(apiFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	dtoFiles := []string{packageHead}
	dtoFiles = append(dtoFiles, pcode.proxySrcPkgAPIStructs...)
	err = ioutil.WriteFile(filePre+"_basic_dto.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	pkgName := pcode.p.name
	pkgApiDesign := pcode.genProxyAPIStructDefAndConstruct()
	receiverPrex := fmt.Sprintf("func (m *%sBasicAPI)", upFirstChar(pkgName))
	var basicAPIProxyBodys string
	for _, basicapi := range pcode.basicAPIPbsMap {

		paramSignStr := basicapi.api.methodReqSign()
		returnSign := basicapi.api.methodReturnSign()
		head := fmt.Sprintf("%s%s (%s)%s {", receiverPrex, basicapi.api.Method, paramSignStr, returnSign)
		body := basicapi.api.proxyBasicFuncBody(pbSrcPkg)

		basicAPIProxyBodys += head + "\n" + body
		println(head, "\n", body)

	}

	dtoFiles = []string{"package wmsbasic", pkgApiDesign, basicAPIProxyBodys}
	err = ioutil.WriteFile(filePre+"_basic_api_impl.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	var endpoints = []string{}
	endpoints = append(endpoints, fmt.Sprintf("// %s endpoint", pcode.p.name))
	endpoints = append(endpoints, "var (")
	for _, api := range pcode.basicAPIPbsMap {
		endpoints = append(endpoints, fmt.Sprintf("%s WmsBasicApi = \"%s\"", api.api.endpointEnum(), api.Path))
	}
	endpoints = append(endpoints, ")")

	dtoFiles = []string{"package wmsbasic"}
	dtoFiles = append(dtoFiles, endpoints...)
	err = ioutil.WriteFile(filePre+"_basic_endpoint.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	if err != nil {
		return err
	}
	return nil
}

type ItemType string

func (i ItemType) IsInnerStruct() bool {
	itemTypeStr := string(i)
	return !strings.Contains(itemTypeStr, ".") &&
		!strings.Contains(itemTypeStr, "[]") &&
		!strings.EqualFold(itemTypeStr, "string") &&
		!strings.EqualFold(itemTypeStr, "int64") &&
		!strings.Contains(itemTypeStr, "map[string]")
}

func (i ItemType) IsOuterStruct() bool {
	itemTypeStr := string(i)
	return strings.Contains(itemTypeStr, ".")
}

func (i ItemType) String() string {
	return string(i)
}
func genProxyAPIPbTpl(base string, pcode *PCode, packageMap map[string]*Package) error {
	module := pcode.p.name
	pkgPbDir := "pb" + module
	//tpl := base + "/" + pkgPbDir
	//tplCommon := base + "/pbcommon"
	//pbBase := "/Users/yunfeizhu/Code/golang/wms-protobuf/apps/basic/pbnewbasic"
	pkgBase := "git.garena.com/shopee/bg-logistics/tianlu/wms-protobuf/apps/basic/pbnewbasic"
	importPkgBase := "apps/basic/pbnewbasic"
	goPkgPath := fmt.Sprintf("%s/%s", pkgBase, pkgPbDir)
	importDtoPkg := fmt.Sprintf("%s/%s/%s_dto.tpl.proto", importPkgBase, pkgPbDir, module)
	importCommonPkg := fmt.Sprintf("%s/%s/entity_entity.tpl.proto", importPkgBase, pkgPbDir)

	//
	//tplHead := "syntax = \"proto2\";"
	innerCommonStructs := []string{}
	for _, pb := range pcode.basicAPIPbs {
		inStructs := pb.api.genInnerDefPkgStructs()
		innerCommonStructs = append(innerCommonStructs, inStructs...)
	}

	var pTpls []string
	pTpls = append(pTpls, "syntax = \"proto2\";")
	pTpls = append(pTpls, fmt.Sprintf("option go_package = \"%s\";", goPkgPath))
	pTpls = append(pTpls, fmt.Sprintf("package %s;", pkgPbDir))
	pTpls = append(pTpls, fmt.Sprintf("import \"%s\";", importDtoPkg))
	pTpls = append(pTpls, fmt.Sprintf("import \"%s\";", importCommonPkg))
	pTpls = append(pTpls, "")
	pTpls = append(pTpls, "")

	apiPbLinesMap := map[string][]string{}
	for _, pb := range pcode.basicAPIPbs {
		println("path: ", pb.Path)
		println("method: ", pb.Method)
		_, ok := apiPbLinesMap[pb.Path]
		if ok {
			continue
		}

		pTpls = append(pTpls, "// "+pb.api.genBasicAPIMethod())
		tplsLines := genAPIPbTpls(pb)
		pTpls = append(pTpls, tplsLines...)

		apiPbLinesMap[pb.Path] = append(apiPbLinesMap[pb.Path], tplsLines...)

		//println(ToPrettyJSON(tplsLines))
		println("")
		println("")
	}

	pcode.apiPbLinesMap = apiPbLinesMap
	pcode.allPbLines = pTpls

	//apiDtoStr := strings.Join(pTpls, "\n")
	//err := ioutil.WriteFile(fmt.Sprintf("%s/%s_api.tpl.proto", tpl, module), []byte(apiDtoStr), 0644)
	//if err != nil {
	//	println(err.Error())
	//}

	types := []string{}
	for _, pb := range pcode.basicAPIPbs {
		for _, field := range pb.ReqFields {
			types = append(types, field.Type)
		}
	}

	uniqTypes := uniqSlice(types...)
	println(ToPrettyJSON(uniqTypes))
	pcode.innerStructTypes = uniqTypes
	inItemStrs, inItemTagsMap := parseInnerStruct(uniqTypes, pcode, packageMap)

	inStructTplDbs := genTplByJsonTagsMap(inItemTagsMap)
	inStructTagTypes := getStructTypeSet(inItemTagsMap)
	pcode.inItemTagsMap = inItemTagsMap

	println("all in item types:\n", ToPrettyJSON(inItemStrs))
	println("all in item types map:\n", ToPrettyJSON(inItemTagsMap))
	println(strings.Join(inStructTplDbs, "\n"))
	println("in struct tyeps:\n  ", ToPrettyJSON(inStructTagTypes))

	var innerTpls []string
	innerTpls = append(innerTpls, "syntax = \"proto2\";")
	innerTpls = append(innerTpls, fmt.Sprintf("option go_package = \"%s\";", goPkgPath))
	innerTpls = append(innerTpls, fmt.Sprintf("package %s;", pkgPbDir))
	innerTpls = append(innerTpls, "")
	innerTpls = append(innerTpls, "")
	innerTpls = append(innerTpls, "")

	innerTpls = append(innerTpls, inStructTplDbs...)

	pcode.innerStructsPbTpls = innerTpls

	//apiCommonStr := strings.Join(innerTpls, "\n")
	//err = ioutil.WriteFile(fmt.Sprintf("%s/%s_dto.tpl.proto", tpl, module), []byte(apiCommonStr), 0644)
	//if err != nil {
	//	println(err.Error())
	//}

	//
	println("out struct types:\n", ToPrettyJSON(pcode.outStructList))
	outItemStrs, ouItemTagsMap := parseOuterStruct(pcode.outStructList, pcode, packageMap)
	println("out struct types str:\n", ToPrettyJSON(outItemStrs))
	println("out struct types json tags:\n", ToPrettyJSON(ouItemTagsMap))
	ouStructTplDbsMaps := genOuterTplByJsonTagsMap(ouItemTagsMap)
	println("out struct types json tags:\n", ToPrettyJSON(ouItemTagsMap))
	//println(strings.Join(ouStructTplDbs, "\n"))

	outPkgPbLinesMap := map[string][]string{}
	for pName, items := range ouStructTplDbsMaps {
		var outerTpls []string
		outerTpls = append(outerTpls, "syntax = \"proto2\";")
		outerTpls = append(outerTpls, fmt.Sprintf("option go_package = \"git.garena.com/shopee/bg-logistics/tianlu/wms-protobuf/apps/basic/pbnewbasic/%s\";", pkgPbDir))
		outerTpls = append(outerTpls, fmt.Sprintf("package %s;", pkgPbDir))
		outerTpls = append(outerTpls, "")
		outerTpls = append(outerTpls, "")
		outerTpls = append(outerTpls, "")
		outerTpls = append(outerTpls, items...)

		outPkgPbLinesMap[pName] = outerTpls

	}
	pcode.ouStructTplDbsMaps = outPkgPbLinesMap

	return nil
}

func genTplFile(base string, pcode *PCode) error {
	module := pcode.p.name
	pkgPbDir := "pb" + module
	tpl := base + "/" + pkgPbDir
	//tplCommon := base + "/pbcommon"
	tplCommon := tpl

	//dto
	apiDtoStr := strings.Join(pcode.allPbLines, "\n")
	err := ioutil.WriteFile(fmt.Sprintf("%s/%s_api.tpl.proto", tpl, module), []byte(apiDtoStr), 0644)
	if err != nil {
		println(err.Error())
	}

	//api
	apiCommonStr := strings.Join(pcode.innerStructsPbTpls, "\n")
	err = ioutil.WriteFile(fmt.Sprintf("%s/%s_dto.tpl.proto", tpl, module), []byte(apiCommonStr), 0644)
	if err != nil {
		println(err.Error())
	}

	//common
	for pName, items := range pcode.ouStructTplDbsMaps {
		commonStr := strings.Join(items, "\n")
		err = ioutil.WriteFile(fmt.Sprintf("%s/%s_entity.tpl.proto", tplCommon, pName), []byte(commonStr), 0644)
		if err != nil {
			println(err.Error())
		}
	}

	//tplFiles := []string{tplHead}
	//tplFiles = append(tplFiles, pcode.proxyAPIsDefs...)
	//err := ioutil.WriteFile(filePre+"_basic_api.go", []byte(strings.Join(tplFiles, "\n")), 0644)
	//if err != nil {
	//	return err
	//}
	//
	//dtoFiles := []string{tplHead}
	//dtoFiles = append(dtoFiles, pcode.proxySrcPkgAPIStructs...)
	//err = ioutil.WriteFile(filePre+"_basic_dto.go", []byte(strings.Join(dtoFiles, "\n")), 0644)
	//if err != nil {
	//	return err
	//}
	return nil
}

//request and resp
func genAPIPbTpls(pb *BASICAPI) []string {
	var lines []string
	lines = append(lines, fmt.Sprintf("message %sRequest{", pb.api.Method))
	for i, field := range pb.ReqFields {
		if field.Type == "context.Context" {
			continue
		}

		item := fmt.Sprintf("%s %s %s = %d;", toPbOption(field.Type), toPbType(field.Type), ToSnakeCase(field.Alias), i)
		lines = append(lines, item)
	}
	lines = append(lines, "}")
	lines = append(lines, fmt.Sprintf("message %sResponse{", pb.api.Method))

	for i, field := range pb.RespTypeStr {
		if field == "*wmserror.WMSError" {
			continue
		}
		fieldType := field
		if strings.Contains(field, ".") {
			fieldType = strings.Split(field, ".")[1]
		}
		alias := fmt.Sprintf("Ret%d", i+1)
		item := fmt.Sprintf("%s %s %s = %d;", toPbOption(field), toPbType(fieldType), ToSnakeCase(alias), i+1)
		lines = append(lines, item)
	}
	lines = append(lines, "}")

	return lines
}

func toPbType(fType string) string {
	fieldType := fType
	if fieldType == "string" {
		return "string"
	}
	if fieldType == "[]string" {
		return "string"
	}
	if fieldType == "[]int64" {
		return "int64"
	} else if fieldType == "int64" {
		return "int64"
	} else if strings.Contains(fieldType, "[]") {
		return toPbSliceStructItemType(fieldType)
	}
	switch fieldType {
	case "string":
		return "string"
	case "int64":
		return "int64"
	case "map[string]interface{}":
		return "MapItem"
	default:
		ftype := strings.ReplaceAll(fieldType, "*", "")
		if strings.Contains(ftype, ".") {
			return strings.Split(ftype, ".")[1] + "Item"
		}
		return ftype + "Item"
	}
}

func toPbSliceStructItemType(fieldType string) string {
	actualType := strings.ReplaceAll(strings.ReplaceAll(fieldType, "[]", ""), "*", "")
	split := strings.Split(actualType, ".")
	pType := actualType
	if len(split) > 1 {
		pType = split[1]
	}
	return pType + "Item"
}

func assignToPbType(field *ReqField) string {
	pbType := field.Type

	fieldType := pbType
	if fieldType == "string" {
		return fmt.Sprintf("convert.String(%s)", field.Alias)
	}
	if fieldType == "[]string" {
		return field.Alias
	}
	if fieldType == "[]int64" {
		return field.Alias
	} else if fieldType == "int64" {
		return fmt.Sprintf("convert.Int64(%s)", field.Alias)

	} else if fieldType == "MapItem" {
		return "mapItemLists"
	} else if fieldType == "map[string]interface{}" {
		return "mapItemLists"
	} else if isSturctItems(fieldType) {
		return fmt.Sprintf("%sItems", field.Alias)
	}

	return fmt.Sprintf("%sItem", field.Alias)
}

func isSturctItems(fieldType string) bool {
	isBasicType := strings.Contains(fieldType, "int64") || strings.Contains(fieldType, "string")
	return strings.Contains(fieldType, "[]") &&
		!isBasicType
}

func parseInnerStruct(uniqTypes []string, pcode *PCode, packageMap map[string]*Package) ([]string, map[string][]*JsonTag) {
	var itemTypes []ItemType
	for _, uniqType := range uniqTypes {
		itemTypes = append(itemTypes, ItemType(uniqType))
	}
	inItemStrs := []string{}
	inItemTagsMap := map[string][]*JsonTag{}
	for _, itemType := range itemTypes {
		if itemType.IsInnerStruct() {
			inItemStrs = append(inItemStrs, string(itemType))
			for _, file := range pcode.p.files {
				itemTypeStr := strings.ReplaceAll(string(itemType), "*", "")
				t, err := file.FindType(itemTypeStr)
				if err != nil && strings.Contains(err.Error(), "is not found") {
					//println(itemType, "is not found")
					continue
				}
				//for _, field := range t.def.(*StructType).Fields() {
				//	println(field.Definition().String())
				//}
				for _, field := range t.def.(*StructType).fields {
					inItemTagsMap[itemTypeStr] = append(inItemTagsMap[itemTypeStr], NewJsonTag(field, packageMap))

				}
				originDef := t.Definition().String()
				withoutHeadDef := strings.ReplaceAll(originDef, "struct {", fmt.Sprintf("struct %s{", itemTypeStr))
				//def = append(def, withoutHeadDef)
				println(withoutHeadDef)
				//println(t)
			}
		}
	}
	return inItemStrs, inItemTagsMap
}

func parseOuterStruct(uniqTypes []string, pcode *PCode, packageMap map[string]*Package) ([]string, map[string][]*JsonTag) {
	var itemTypes []ItemType
	for _, uniqType := range uniqTypes {
		itemTypes = append(itemTypes, ItemType(uniqType))
	}
	inItemStrs := []string{}
	outItemTagsMap := map[string][]*JsonTag{}
	for _, itemType := range itemTypes {
		if itemType.IsOuterStruct() {
			actualType := strings.ReplaceAll(strings.ReplaceAll(itemType.String(), "[]", ""), "*", "")

			segs := strings.Split(actualType, ".")
			typePackage := strings.ReplaceAll(segs[0], "*", "")
			for packagePath, p := range packageMap {
				pathSegs := strings.Split(packagePath, "/")
				if pathSegs[len(pathSegs)-1] == typePackage {
					ktype, err := p.FindType(segs[1])
					if err != nil && strings.Contains(err.Error(), "is not found") {
						//println(itemType, "is not found")
						continue
					}

					if structType, ok := ktype.def.(*StructType); ok {
						inItemStrs = append(inItemStrs, actualType)
						if _, exist := outItemTagsMap[actualType]; exist {
							continue
						}
						for _, field := range structType.fields {
							outItemTagsMap[actualType] = append(outItemTagsMap[actualType], NewJsonTag(field, packageMap))
						}
					} else {
						println("out struct is not a struct type; %s", itemType)
					}
				}
			}
			for _, file := range pcode.p.files {
				itemTypeStr := strings.ReplaceAll(string(itemType), "*", "")
				t, err := file.FindType(itemTypeStr)
				if err != nil && strings.Contains(err.Error(), "is not found") {
					//println(itemType, "is not found")
					continue
				}
				//for _, field := range t.def.(*StructType).Fields() {
				//	println(field.Definition().String())
				//}
				for _, field := range t.def.(*StructType).fields {
					outItemTagsMap[itemTypeStr] = append(outItemTagsMap[itemTypeStr], NewJsonTag(field, packageMap))

				}
				originDef := t.Definition().String()
				withoutHeadDef := strings.ReplaceAll(originDef, "struct {", fmt.Sprintf("struct %s{", itemTypeStr))
				//def = append(def, withoutHeadDef)
				println(withoutHeadDef)
				//println(t)
			}
		}
	}
	return inItemStrs, outItemTagsMap
}

func getStructTypeSet(tagsMap map[string][]*JsonTag) []string {
	var items []string
	for _, tags := range tagsMap {
		for _, tag := range tags {
			items = append(items, tag.KeyType)
		}
	}
	return uniqSlice(items...)
}

func genTplByJsonTagsMap(tagsMap map[string][]*JsonTag) []string {

	var items []string
	for objName, tags := range tagsMap {
		item := []string{}
		tplHead := fmt.Sprintf("message  %sItem{", objName)
		var pbFields = []string{}
		for i, tag := range tags {
			fieldStr := tag.ToPbFieldDef(i)
			pbFields = append(pbFields, fieldStr)
		}
		tplFoot := fmt.Sprintf("}")

		item = append(item, tplHead)
		item = append(item, pbFields...)
		item = append(item, tplFoot)
		items = append(items, strings.Join(item, "\n"))
	}
	return items
}

func genOuterTplByJsonTagsMap(tagsMap map[string][]*JsonTag) map[string][]string {

	var retItemMaps = map[string][]string{}
	for objName, tags := range tagsMap {
		segs := strings.Split(objName, ".")
		packageName := segs[0]
		vType := segs[1]
		var item []string
		tplHead := fmt.Sprintf("message  %sItem{", vType)
		var pbFields = []string{}
		for i, tag := range tags {
			fieldStr := tag.ToPbFieldDef(i)
			pbFields = append(pbFields, fieldStr)
		}
		tplFoot := fmt.Sprintf("}")

		item = append(item, tplHead)
		item = append(item, pbFields...)
		item = append(item, tplFoot)
		retItemMaps[packageName] = append(retItemMaps[packageName], item...)
	}
	return retItemMaps
}

type JsonTag struct {
	Key     string
	KeyType string
	JsonTag string
	isValid bool
}

func (t JsonTag) ToPbFieldDef(keyIdex int) string {
	return fmt.Sprintf("%s %s %s = %d;", t.ToPbOption(), t.toPbType(), t.Key, keyIdex+1)
}

func (t JsonTag) ToPbOption() string {
	return toPbOption(t.KeyType)
}

func toPbOption(t string) string {
	if strings.Contains(t, "[") {
		return "repeated"
	}
	return "optional"
}

func (t JsonTag) toPbType() string {
	fieldType := strings.ReplaceAll(t.KeyType, "*", "")

	switch fieldType {
	case "string":
		return "string"
	case "int64":
		return "int64"
	default:
		return fieldType
	}
}

//tag: like json:"whs_id,omitempty"
func NewJsonTag(field *Field, packageMap map[string]*Package) *JsonTag {
	tag := field.Tags()
	keyType := field.def.String()
	key := strings.Split(tag.Get("json"), ",")[0]
	//segs := strings.Split(tag, ":")
	//isValid := true
	//if len(segs) != 2 || segs[0] != "json" {
	//	isValid = false
	//}
	//tagVal := segs[1]
	//tagValWithoutEmpty := strings.ReplaceAll(tagVal, "\"", "")
	//
	//key := strings.Split(tagValWithoutEmpty, ",")[0]

	//如： "*constant.SkuSizeType", 转换成int64\或者string
	if !strings.Contains(keyType, "[") && strings.Contains(keyType, ".") {
		segs := strings.Split(keyType, ".")
		typePackage := strings.ReplaceAll(segs[0], "*", "")
		for packagePath, p := range packageMap {
			pathSegs := strings.Split(packagePath, "/")
			if pathSegs[len(pathSegs)-1] == typePackage {
				ktype, err := p.FindType(segs[1])
				if err == nil {
					ctType := ktype.def.String()
					println(fmt.Sprintf("keyType:%s convert to %s", keyType, ctType))
					keyType = ctType
				}
			}
		}
	}

	isValid := len(key) > 0

	return &JsonTag{
		Key:     key,
		KeyType: keyType,
		isValid: isValid,
	}
}

func uniqSlice(types ...string) []string {
	set := hashset.New()
	for _, s := range types {
		set.Add(s)
	}

	var ret []string
	for _, i := range set.Values() {
		ret = append(ret, i.(string))
	}
	return ret
}

func genSrcProxyCodeFile(srcPath string, pcode *PCode) error {
	filePre := srcPath + "/" + pcode.p.name

	packageHead := fmt.Sprintf("package %s", pcode.p.name)
	apiFiles := []string{packageHead}
	apiFiles = append(apiFiles, pcode.srcPkgProxyFuncs...)
	err := ioutil.WriteFile(filePre+"_proxy_handler.go", []byte(strings.Join(apiFiles, "\n")), 0644)
	if err != nil {
		return err
	}

	return nil
}

type SrcEndPoint string

func NewSrcEndPoint(p, f string) SrcEndPoint {
	return SrcEndPoint(fmt.Sprintf("%s#%s", p, f))
}

type PCode struct {
	p *Package
	//代理包定义
	srcPkgProxyFuncs []string
	//源包代理方法体
	srcPkgProxyFuncMap map[SrcEndPoint]string

	outStructList []string
	//代理的包纬度接口定义
	proxyAPIsDefs []string
	//代理的包纬度接口struct
	proxySrcPkgAPIStructs []string

	//所有的API
	basicAPIPbs []*BASICAPI

	basicAPIDefMap  map[SrcEndPoint]string
	basicAPIReqsMap map[SrcEndPoint]string
	basicAPIPbsMap  map[SrcEndPoint]*BASICAPI

	//API 对应的pb定义
	allPbLines         []string
	apiPbLinesMap      map[string][]string
	innerStructTypes   []string
	inItemTagsMap      map[string][]*JsonTag
	innerStructsPbTpls []string

	//outer struct
	ouStructTplDbsMaps map[string][]string
}

func (pcode PCode) genProxyAPIStructDefAndConstruct() string {
	pkgName := pcode.p.name
	actualApiName := fmt.Sprintf("%sBasicAPI", upFirstChar(pkgName))
	apiName := fmt.Sprintf("%sAPI", upFirstChar(pkgName))
	objSign := fmt.Sprintf(" type %s struct{", actualApiName)
	objSign += "\n\t Client Client"
	objSign += "\n\t }"
	//func NewMsizetypeBasicAPI() *MsizetypeBasicAPI {
	//	return &MsizetypeBasicAPI{}
	//}

	objConsturcts := []string{}
	newStr := fmt.Sprintf("func New%s() %s {", apiName, apiName)
	returnStr := fmt.Sprintf("return &%s{", actualApiName)
	returnStr += "\n\tClient: NewClient(),"
	returnStr += "\n\t}"

	objConsturcts = append(objConsturcts, newStr)
	objConsturcts = append(objConsturcts, returnStr)
	objConsturcts = append(objConsturcts, "}")

	return objSign + "\n" + strings.Join(objConsturcts, "\n")

}

func parsePCode(p *Package) *PCode {
	code := &PCode{
		p: p,
	}
	inStructSet := hashset.New()
	outStructSet := hashset.New()
	apis := parseFuncs(p, inStructSet, outStructSet)

	var funcDefs []string
	var basicAPIs []string
	var basicAPIReqs []string
	var basicAPIPbs []*BASICAPI

	var apiFuncDefsMap = map[SrcEndPoint]string{}
	var basicAPIsMap = map[SrcEndPoint]string{}
	var basicAPIReqsMap = map[SrcEndPoint]string{}
	var basicAPIPbsMap = map[SrcEndPoint]*BASICAPI{}
	for _, api := range apis {
		if !isExported(api.Method) {
			//println("method is not exported: ", api.Method)
			continue
		}
		endpoint := NewSrcEndPoint(api.Pkg.name, api.Method)
		funcDefs = append(funcDefs, api.proxyFuncBody2())
		apiFuncDefsMap[endpoint] = api.proxyFuncBody2()

		basicAPIs = append(basicAPIs, api.BasicAPIInterfaceSignWithComment())
		basicAPIsMap[endpoint] = api.BasicAPIInterfaceSignWithComment()

		basicAPIReqs = append(basicAPIReqs, api.proxyPbAPIReq())
		basicAPIReqsMap[endpoint] = api.proxyPbAPIReq()

		basicAPIPbs = append(basicAPIPbs, api.proxyPbAPI())
		basicAPIPbsMap[endpoint] = api.proxyPbAPI()
	}

	code.srcPkgProxyFuncMap = apiFuncDefsMap
	code.basicAPIDefMap = basicAPIsMap

	code.basicAPIReqsMap = basicAPIReqsMap
	code.basicAPIPbsMap = basicAPIPbsMap

	//prttryStr("func body", strings.Join(funcDefs, "\n"))
	code.proxyAPIsDefs = buildPackageProxyBasicAPI(p, uniqSlice(basicAPIs...))
	code.basicAPIPbs = basicAPIPbs
	//源包
	code.srcPkgProxyFuncs = funcDefs
	//代理包
	code.proxySrcPkgAPIStructs = pReqItemStrs(apis)

	//prttryStr("basic api ", strings.Join(basicAPIs, "\n\n"))
	//prttryStr("basic api req", strings.Join(basicAPIReqs, "\n\n"))
	var outStructTypeList []string
	for _, i := range inStructSet.Values() {
		println(p.name, " inner struct", i.(string))
	}
	for _, i := range outStructSet.Values() {
		//println(p.name, " out struct", i.(string))
		outStructTypeList = append(outStructTypeList, i.(string))
	}
	code.outStructList = outStructTypeList

	return code

}

func pReqItemStrs(apis []*API) []string {
	reqDefSet := hashset.New()
	for _, api := range apis {
		if !isExported(api.Method) {
			continue
		}
		for _, itemStr := range api.proxyProxyAPIReqItem() {
			reqDefSet.Add(itemStr)
		}
	}
	reqItems := []string{}
	for _, i := range reqDefSet.Values() {
		reqItems = append(reqItems, i.(string))
	}
	return reqItems
}

func buildPackageProxyBasicAPI(p *Package, basicAPIs []string) []string {
	var wmsbasicAPI []string
	wmsbasicAPI = append(wmsbasicAPI, fmt.Sprintf("type %sAPI interface {", upFirstChar(p.name)))
	wmsbasicAPI = append(wmsbasicAPI, basicAPIs...)
	wmsbasicAPI = append(wmsbasicAPI, "}")
	return wmsbasicAPI
}

func parseFuncs(p *Package, inStructSet *hashset.Set, outStructSet *hashset.Set) []*API {
	var apis []*API
	for _, function := range p.Functions() {
		receiver := function.receiver
		//todo filter proxy_main 方法

		if receiver == nil {
			println(function.name, " is not receiver")
			continue
		}
		//like skuManager
		originObjName := receiver.def.String()
		receiverName := originObjName + "Proxy"
		receiverAlias := receiver.name
		funcWithReciver := fmt.Sprintf("func (%v %s) ", receiverAlias, receiverName) + function.name
		getDefinitionWithName := function.def.getDefinitionWithName(funcWithReciver)
		//println("getDefinitionWithName:=", getDefinitionWithName)

		api := genReqAndResp(function)
		api.FuncSignStr = getDefinitionWithName
		api.ReceiverAlias = receiverAlias
		api.ReceiverName = strings.ReplaceAll(originObjName, "*", "")
		api.Pkg = p
		apis = append(apis, api)

		//println(ToPrettyJSON(api))

		for _, i := range api.genInnerDefPkgStructs() {
			inStructSet.Add(i)
		}
		for _, i := range api.genOuterDefPkgStructs() {
			outStructSet.Add(i)
		}
	}
	return apis
}

func prttryStr(label string, body string) {
	println()
	println(color.InGreen(fmt.Sprintf("====================== [%s] start =====================", label)))
	println(body)
	println(color.InGreen(fmt.Sprintf("====================== [%s] end =====================", label)))
	println()

}

type API struct {
	Path          string
	Package       string
	Method        string
	Req           map[string]string
	ReqFields     []*ReqField
	Resp          []string
	Func          *FuncType
	FuncSignStr   string
	ReceiverAlias string
	ReceiverName  string
	Pkg           *Package
}

type BASICAPI struct {
	Path        string
	Package     string
	Method      string
	Req         map[string]string
	ReqFields   []*ReqField
	RespTypeStr []string
	Pkg         *Package
	api         API
}

type ReqField struct {
	Alias string
	Type  string
}

func (api API) proxyFuncBody() string {
	var bodyStr []string
	bodyStr = append(bodyStr, api.FuncSignStr+"{")

	//var ret1 []*entity.CellSizeType
	//var ret2 int64
	//var ret3 *wmserror.WMSError
	for i, ret := range api.Resp {
		v := fmt.Sprintf("var %s %s", fmt.Sprintf("ret%d", i+1), ret)
		bodyStr = append(bodyStr, v)
	}

	//
	//originHandler := func(ctx context.Context) {
	//	ret1, ret2, ret3 = c.origin.SearchCellSizeList(ctx, whsID)
	//}
	retParams := []string{}
	for i := range api.Resp {
		retParams = append(retParams, fmt.Sprintf("ret%d ", i+1))
	}
	rets := strings.Join(retParams, ", ")

	bodyStr = append(bodyStr, "\toriginHandler := func(ctx context.Context) {")
	params := []string{}
	for _, field := range api.ReqFields {
		params = append(params, field.Alias)
	}
	paramsStr := strings.Join(params, ", ")

	callOriginal := fmt.Sprintf("= %s.%s.%s(%s)", api.ReceiverAlias, lowerFirstChar(api.ReceiverName), api.Method, paramsStr)
	bodyStr = append(bodyStr, rets+callOriginal)
	bodyStr = append(bodyStr, "\t}")

	//proxyHandler := func(ctx context.Context) *wmserror.WMSError {
	//	req := &pbmsizetype.SearchCellSizeListReq{
	//		WhsID: whsID,
	//	}

	bodyStr = append(bodyStr, "proxyHandler := func(ctx context.Context) *wmserror.WMSError {")
	bodyStr = append(bodyStr, fmt.Sprintf("req := &pb%s.%sReq{", api.Package, api.Method))
	var reqFieldsStr []string
	for _, field := range api.ReqFields {
		fieldParam := field.Alias
		fieldType := upFirstChar(fieldParam)
		reqFieldsStr = append(reqFieldsStr, fmt.Sprintf("\t%s:%s,", fieldType, fieldParam))
	}
	bodyStr = append(bodyStr, reqFieldsStr...)
	bodyStr = append(bodyStr, "}")

	//	apiResp, err := c.basicAPI.SearchCellSizeList(ctx, req)
	//	if err != nil {
	//		return err.Mark()
	//	}
	var callProxy string
	if len(api.Resp) > 1 {
		callProxy = fmt.Sprintf("apiResp, err := %s.basicAPI.%s(ctx, req)", api.ReceiverAlias, api.Method)
	} else {
		callProxy = fmt.Sprintf("err := %s.basicAPI.%s(ctx, req)", api.ReceiverAlias, api.Method)
	}
	bodyStr = append(bodyStr, callProxy)
	bodyStr = append(bodyStr, "\tif err != nil {")
	bodyStr = append(bodyStr, "\treturn err.Mark()")
	bodyStr = append(bodyStr, "\t}")

	//	ret1, ret2, ret3 = apiResp.GetRet1(), apiResp.GetRet2(), apiResp.GetRet3()
	//	return nil
	//}
	proxyRets := []string{}
	proxyRetParams := []string{}
	for i := range api.Resp {
		if i == len(api.Resp)-1 {
			continue
		}
		proxyRets = append(proxyRets, fmt.Sprintf("apiResp.GetRet%d()", i))
		proxyRetParams = append(proxyRetParams, fmt.Sprintf("ret%d", i))
	}
	if len(proxyRetParams) > 0 {
		bodyStr = append(bodyStr, fmt.Sprintf("%s = %s", strings.Join(proxyRetParams, ", "), strings.Join(proxyRets, ", ")))
	}
	bodyStr = append(bodyStr, "return nil")
	bodyStr = append(bodyStr, "}")

	//
	//endPoint := "SearchCellSizeList"
	//doBasicHandler(ctx, endPoint, originHandler, proxyHandler)
	//return ret1, ret2, ret3

	bodyStr = append(bodyStr, fmt.Sprintf("endPoint := \"%s\"", api.Method))
	if api.genBasicAPIMethod() == "GET" {
		bodyStr = append(bodyStr, "getBasicHandler()(ctx, endPoint, originHandler, proxyHandler, apiIdempotent)")
	} else {
		bodyStr = append(bodyStr, "getBasicHandler()(ctx, endPoint, originHandler, proxyHandler)")
	}
	bodyStr = append(bodyStr, "return "+rets)
	bodyStr = append(bodyStr, "}")

	return strings.Join(bodyStr, "\n")
}
func (api API) proxyBasicFuncBody(pbPkg *Package) string {

	module := api.Pkg.name
	var bodyStr []string

	//var ret1 []*entity.CellSizeType
	//var ret2 int64
	//var err *wmserror.WMSError

	retItemVars := api.apiRets()
	retItems := api.apiRetDefs()

	bodyStr = append(bodyStr, retItems...)
	bodyStr = append(bodyStr, "")

	//
	//rets := strings.Join(retItems, ", ")

	copyLine := "jsErr := copier.Copy(%s,%s)"

	var params []string
	isDefineJsErr := false
	for _, field := range api.ReqFields {
		if field.Type == "context.Context" {
			continue
		}

		if field.Type == "map[string]interface{}" {
			params = append(params, fmt.Sprintf("mapItemLists,err := convertToMapUpdateItems(%s)", field.Alias))

			params = append(params, "if err != nil {")
			if len(retItemVars) > 1 {
				errMsg := "\t\treturn  %s, wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())"
				params = append(params, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","), ""))
			} else {
				params = append(params, "\t\treturn  wmserror.NewError(constant.ErrBadRequest, \"update map convert to item list err:%v\", err.Error())")
			}
			params = append(params, "}")
			continue
		}

		if strings.Contains(toPbType(field.Type), "Item") && field.Type != "*paginator.PageIn" {
			pbType := assignToPbType(field)
			if isSturctItems(field.Type) {

				params = append(params, fmt.Sprintf("%s:=[]*pb%s.%s{}", pbType, module, toPbSliceStructItemType(field.Type)))
			} else {
				params = append(params, fmt.Sprintf("%s:=&pb%s.%s{}", pbType, module, toPbSliceStructItemType(field.Type)))
			}
			//
			//jsErr := copier.Copy(nil, nil)
			//if jsErr != nil {
			//	return ret1, wmserror.NewError(constant.ErrBadRequest, "json convert err:%v", jsErr.Error())
			//}

			if isDefineJsErr {
				copyLine = strings.ReplaceAll(copyLine, ":", "")
			} else {
				isDefineJsErr = true
			}
			params = append(params, fmt.Sprintf(copyLine, field.Alias, pbType))

			errLines := dealCopyErrLines(retItemVars)
			params = append(params, errLines...)
			params = append(params, "}")
		}

		//*paginator.PageIn
		if field.Type == "*paginator.PageIn" {
			pbType := assignToPbType(field)
			params = append(params, fmt.Sprintf("%s:=&pb%s.%s{", pbType, module, toPbSliceStructItemType(field.Type)))
			//		Pageno:     convert.Int64(pageIn.Pageno),
			//		Count:      convert.Int64(pageIn.Count),
			//		OrderBy:    convert.String(pageIn.OrderBy),
			//		IsGetTotal: convert.Bool(pageIn.IsGetTotal),
			alias := field.Alias
			params = append(params, fmt.Sprintf("\tPageno:     convert.Int64(%s.Pageno),", alias))
			params = append(params, fmt.Sprintf("\tCount:     convert.Int64(%s.Count),", alias))
			params = append(params, fmt.Sprintf("\tOrderBy:     convert.String(%s.OrderBy),", alias))
			params = append(params, fmt.Sprintf("\tIsGetTotal:     convert.Bool(%s.IsGetTotal),", alias))
			params = append(params, "}")
			//
		}

		//item := fmt.Sprintf("\t%s:%s,", upFirstChar(field.Alias), assignToPbType(field))
		//params = append(params, item)
	}

	itemTypeMap := map[string]map[string]*Field{}
	pbReqType := fmt.Sprintf("%sRequest", api.Method)
	api.parsePbType(pbPkg, pbReqType, itemTypeMap)

	params = append(params, "\n// do requets")
	params = append(params, fmt.Sprintf("req:=&pb%s.%sRequest{", module, api.Method))
	reqPbTypesMap := itemTypeMap[pbReqType]
	for _, field := range api.ReqFields {
		if field.Type == "context.Context" {
			continue
		}
		fieldType := strings.ToLower(field.Alias)
		pbType := upFirstChar(field.Alias)
		if reqPbTypesMap[fieldType] != nil {
			pbType = reqPbTypesMap[fieldType].name
		}

		item := fmt.Sprintf("\t%s:%s,", pbType, assignToPbType(field))
		params = append(params, item)
	}
	params = append(params, "}")

	resps := []string{}
	resps = append(resps, fmt.Sprintf("resp:=&pb%s.%sResponse{}", module, api.Method))

	bodyStr = append(bodyStr, params...)
	bodyStr = append(bodyStr, resps...)

	method := api.genBasicAPIMethod()
	method = upFirstChar(strings.ToLower(method))
	endPointEnum := api.endpointEnum()
	bodyStr = append(bodyStr, fmt.Sprintf("\t_, err = m.Client.%s(ctx, %s, req, resp, DefaultTimeOut)", method, endPointEnum))

	bodyStr = append(bodyStr, "\tif err != nil {")
	//	if err != nil {
	//		return err.Mark()
	//	}
	if len(api.apiRets()) > 1 {
		errMsg := "\t\treturn  %s, err.Mark()"
		bodyStr = append(bodyStr, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ",")))
	} else {
		bodyStr = append(bodyStr, "return err.Mark()")
	}

	bodyStr = append(bodyStr, "\t}")

	//todo 赋值返回值
	respAssgins := []string{}
	if len(api.apiRets()) > 0 {
		for i, ret := range api.Resp {
			if ret == "*wmserror.WMSError" {
				continue
			}
			retIdex := i + 1
			curRet := fmt.Sprintf("ret%d", retIdex)
			respRet := fmt.Sprintf("resp.GetRet%d()", retIdex)
			rawRespRet := fmt.Sprintf("resp.Ret%d", retIdex)
			if isNormalType(ret) {
				assign := fmt.Sprintf("%s = %s", curRet, respRet)
				respAssgins = append(respAssgins, assign)
			} else {
				if isDefineJsErr {
					copyLine = strings.ReplaceAll(copyLine, ":", "")
				} else {
					isDefineJsErr = true
				}

				respAssgins = append(respAssgins, fmt.Sprintf("if %s !=nil{", rawRespRet))
				respAssgins = append(respAssgins, fmt.Sprintf(copyLine, respRet, "&"+curRet))
				errLines := dealCopyErrLines(retItemVars)
				respAssgins = append(respAssgins, errLines...)
				respAssgins = append(respAssgins, "}")
				respAssgins = append(respAssgins, "}")
			}
		}
	}
	bodyStr = append(bodyStr, "")
	if len(retItemVars) > 1 {
		bodyStr = append(bodyStr, "// 转换返回值")
	}

	bodyStr = append(bodyStr, respAssgins...)

	returnVal := "\t\treturn   nil"
	if len(retItemVars) > 1 {
		errMsg := "\t\treturn  %s, nil"
		returnVal = fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","))
	}

	bodyStr = append(bodyStr, returnVal)

	bodyStr = append(bodyStr, "\t}")
	bodyStr = append(bodyStr, "\n")

	return strings.Join(bodyStr, "\n")
}

func (api API) endpointEnum() string {
	endPointEnum := upFirstChar(api.Pkg.name) + api.Method
	return endPointEnum
}

func dealCopyErrLines(retItemVars []string) []string {
	var params []string
	params = append(params, "if jsErr != nil {")
	if len(retItemVars) > 1 {
		errMsg := "\t\treturn  %s, wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())"
		params = append(params, fmt.Sprintf(errMsg, strings.Join(retItemVars[0:len(retItemVars)-1], ","), ""))

	} else {
		params = append(params, "\t\treturn  wmserror.NewError(constant.ErrBadRequest, \"json convert err:%v\", jsErr.Error())")
	}
	return params
}

func isNormalType(fieldTypeStr string) bool {
	normalTypes := []string{
		"int64",
		"string",
		"[]string",
		"[]int64",
	}
	for _, normalType := range normalTypes {
		if normalType == fieldTypeStr {
			return true
		}
	}
	return false
}

func (api API) parsePbType(pbPkg *Package, pbReqType string, itemTypeMap map[string]map[string]*Field) {
	if pbPkg != nil {
		pbItemType, err := pbPkg.FindType(pbReqType)
		if err != nil {
			println(err.Error())
		}
		keyToMap := map[string]*Field{}
		if objType, ok := pbItemType.def.(*StructType); ok {
			for _, field := range objType.fields {
				keyToMap[strings.ToLower(field.name)] = field
			}
		}
		itemTypeMap[pbReqType] = keyToMap
	}
}

func (api API) apiRets() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("ret%d", i+1)
		if ret == "*wmserror.WMSError" {
			v = "err"
		}
		rets = append(rets, v)
	}
	return rets
}

func (api API) apiRetDefs() []string {
	rets := []string{}
	for i, ret := range api.Resp {
		v := fmt.Sprintf("var %s  %s", fmt.Sprintf("ret%d", i+1), ret)
		if ret == "*wmserror.WMSError" {
			v = "var err *wmserror.WMSError"
		} else {
			if !isNormalType(ret) {
				if isSturctItems(ret) {
					v = fmt.Sprintf("var %s = %s{}", fmt.Sprintf("ret%d", i+1), ret)
				} else {
					ret = strings.ReplaceAll(ret, "*", "&")
					v = fmt.Sprintf("var %s = %s{}", fmt.Sprintf("ret%d", i+1), ret)
				}
			}
		}

		rets = append(rets, v)
	}
	return rets
}

func (api API) proxyFuncBody2() string {
	var bodyStr []string
	bodyStr = append(bodyStr, api.FuncSignStr+"{")

	//var ret1 []*entity.CellSizeType
	//var ret2 int64
	//var ret3 *wmserror.WMSError
	for i, ret := range api.Resp {
		v := fmt.Sprintf("var %s %s", fmt.Sprintf("ret%d", i), ret)
		bodyStr = append(bodyStr, v)
	}

	//
	//originHandler := func(ctx context.Context) {
	//	ret1, ret2, ret3 = c.origin.SearchCellSizeList(ctx, whsID)
	//}
	retParams := []string{}
	for i := range api.Resp {
		retParams = append(retParams, fmt.Sprintf("ret%d ", i))
	}
	rets := strings.Join(retParams, ", ")

	bodyStr = append(bodyStr, "\toriginHandler := func(ctx context.Context) {")
	params := []string{}
	for _, field := range api.ReqFields {
		params = append(params, field.Alias)
	}
	paramsStr := strings.Join(params, ", ")

	callOriginal := fmt.Sprintf("= %s.%s.%s(%s)", api.ReceiverAlias, lowerFirstChar(api.ReceiverName), api.Method, paramsStr)
	bodyStr = append(bodyStr, rets+callOriginal)
	bodyStr = append(bodyStr, "\t}")

	bodyStr = append(bodyStr, "\tproxyHandler := func(ctx context.Context) *wmserror.WMSError{")
	proxyParams := []string{}
	for _, field := range api.ReqFields {
		if api.isNeedRedefineStruct(field) {
			copyReqs := []string{}

			reqStr := fmt.Sprintf("%sReq", field.Alias)
			//req := &wmsbasic.SearchCellSizeConditionItem{}
			reqItemType := field.Type
			if strings.Contains(reqItemType, "*") && !strings.Contains(reqItemType, "[") {
				reqItemType = strings.Split(reqItemType, "*")[1]
			}

			copyReqs = append(copyReqs, fmt.Sprintf("%s := &wmsbasic.%sItem{}", reqStr, reqItemType))
			//ctErr := copier.Copy(condition, &req)
			//todo 是否是指针
			copyReqs = append(copyReqs, fmt.Sprintf("ctErr := copier.Copy(%s, %s)", field.Alias, reqStr))
			//if ctErr != nil {
			//	return wmserror.NewError(constant.ErrJsonDecodeFail, ctErr.Error())
			//}
			copyReqs = append(copyReqs, "if ctErr != nil {")
			copyReqs = append(copyReqs, "return wmserror.NewError(constant.ErrJsonDecodeFail, ctErr.Error())")
			copyReqs = append(copyReqs, "}")

			bodyStr = append(bodyStr, strings.Join(copyReqs, "\n"))
			proxyParams = append(proxyParams, reqStr)
		} else {
			proxyParams = append(proxyParams, field.Alias)
		}
	}
	proxyParamsStr := strings.Join(proxyParams, ", ")

	proxyCallOriginal := fmt.Sprintf("= %s.%sProxyAPI.%s(%s)", api.ReceiverAlias, lowerFirstChar(api.ReceiverName), api.Method, proxyParamsStr)
	bodyStr = append(bodyStr, rets+proxyCallOriginal)
	bodyStr = append(bodyStr, fmt.Sprintf("return %s", retParams[len(retParams)-1]))
	bodyStr = append(bodyStr, "\t}")

	bodyStr = append(bodyStr, fmt.Sprintf("endPoint := \"%s\"", api.Method))
	if api.genBasicAPIMethod() == "GET" {
		bodyStr = append(bodyStr, "getBasicHandler()(ctx, endPoint, originHandler, proxyHandler, apiIdempotent)")
	} else {
		bodyStr = append(bodyStr, "getBasicHandler()(ctx, endPoint, originHandler, proxyHandler)")
	}
	bodyStr = append(bodyStr, "return "+rets)
	bodyStr = append(bodyStr, "}")

	return strings.Join(bodyStr, "\n")
}
func (api API) proxyPbAPIReq() string {
	basicAPI := &BASICAPI{
		Package:     "",
		Req:         nil,
		ReqFields:   nil,
		RespTypeStr: nil,
		Pkg:         nil,
	}

	basicAPI.Method = api.genBasicAPIMethod()
	basicAPI.Path = "wms-v2-basic/" + api.Path + "/" + api.Method
	var reqFieldStr []string
	reqFieldStr = append(reqFieldStr, fmt.Sprintf("type %s%sReq struct{", upFirstChar(api.Package), api.Method))

	innerStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldParam := field.Alias
		fieldParamDef := upFirstChar(fieldParam)
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		//if !strings.Contains(fieldType, ".") &&
		//	fieldType != "string" &&
		//	fieldType != "int64" &&
		//	fieldType != "[]string" &&
		//	fieldType != "[]int64" {
		if api.isNeedRedefineStruct(field) {

			innerStructset.Add(strings.ReplaceAll(fieldType, "*", ""))
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %sItem `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		} else {
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %s `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		}
	}

	reqFieldStr = append(reqFieldStr, "}")
	for _, i := range innerStructset.Values() {
		fieldType := i.(string)
		depStructFieldType := api.genInnerPkgStructDef(fieldType)

		reqFieldStr = append(reqFieldStr, depStructFieldType)
	}

	reqDef := strings.Join(reqFieldStr, "\n")
	ret := reqDef
	return ret

}

func (api API) proxyPbAPI() *BASICAPI {
	basicAPI := &BASICAPI{
		Package:     "",
		Req:         nil,
		ReqFields:   nil,
		RespTypeStr: nil,
		Pkg:         nil,
		api:         api,
	}

	basicAPI.Package = api.Package
	basicAPI.Method = api.genBasicAPIMethod()
	basicAPI.Path = "wms-v2-basic/" + api.Path + "/" + api.Method
	basicAPI.ReqFields = api.ReqFields
	basicAPI.RespTypeStr = api.Resp
	return basicAPI

}

func (api API) proxyProxyAPIReqItem() []string {
	basicAPI := &BASICAPI{}

	basicAPI.Path = "wms-v2-basic/" + api.Path + "/" + api.Method
	var reqFieldStr []string
	reqFieldStr = append(reqFieldStr, fmt.Sprintf("type %s%sReq struct{", upFirstChar(api.Package), api.Method))

	innerStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldParam := field.Alias
		fieldParamDef := upFirstChar(fieldParam)
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		//if !strings.Contains(fieldType, ".") &&
		//	fieldType != "string" &&
		//	fieldType != "int64" &&
		//	fieldType != "[]string" &&
		//	fieldType != "[]int64" {
		if api.isNeedRedefineStruct(field) {

			innerStructset.Add(strings.ReplaceAll(fieldType, "*", ""))
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %sItem `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		} else {
			reqFieldStr = append(reqFieldStr, fmt.Sprintf("\t%s %s `json:\"%s,omitempty\"`", fieldParamDef, fieldType, ToSnakeCase(fieldParamDef)))
		}
	}

	reqFieldStr = append(reqFieldStr, "}")
	var itemFields []string
	for _, i := range innerStructset.Values() {
		fieldType := i.(string)
		depStructFieldType := api.genInnerPkgStructDef(fieldType)

		itemFields = append(itemFields, depStructFieldType)
	}

	return itemFields

}

func (api API) BasicAPIInterfaceSignWithComment() string {
	//prefix := "// proxy 原来 msku.SKUManager GetSkuSetForHighValueByWhsID 的请求\n "
	prefix := fmt.Sprintf("// %s \n// proxy 原来 %s.%s %s 的请求\n ", api.Method, api.Package, api.ReceiverName, api.Method)
	//println(prefix)
	sign := api.proxyBasicSign()
	return prefix + sign
}

func (api API) proxyBasicSign() string {
	sign := fmt.Sprintf("%s(%s) %s", api.Method, api.methodReqSign(), api.methodReturnSign())
	return sign
}

func (api API) methodReturnSign() string {
	var retParams []string
	for i := range api.Resp {
		retParams = append(retParams, fmt.Sprintf("%s ", api.Resp[i]))
	}
	var retSign = ""
	if len(retParams) > 1 {
		retSign = fmt.Sprintf("(%s)", strings.Join(retParams, ", "))
	} else {
		retSign = retParams[0]
	}
	return retSign
}
func (api API) genInnerDefPkgStructs() []string {
	innerStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		if !strings.Contains(fieldType, ".") && fieldType != "string" && fieldType != "int64" {
			innerStructset.Add(strings.ReplaceAll(fieldType, "*", ""))
		}
	}
	var items []string
	for _, i := range innerStructset.Values() {
		fieldType := i.(string)
		items = append(items, fieldType)
	}
	return items
}
func (api API) genOuterDefPkgStructs() []string {
	outStructset := hashset.New()
	for _, field := range api.ReqFields {
		fieldType := field.Type
		if fieldType == "context.Context" {
			continue
		}

		//当前包下的struct
		if strings.Contains(fieldType, ".") {
			outStructset.Add(fieldType)
		}
	}
	for _, field := range api.Resp {

		//当前包下的struct
		if strings.Contains(field, ".") {
			outStructset.Add(field)
		}
	}
	var items []string
	for _, i := range outStructset.Values() {
		fieldType := i.(string)
		items = append(items, fieldType)
	}
	return items
}
func (api API) genInnerPkgStructDef(fieldType string) string {
	var def = []string{}
	defHead := fmt.Sprintf("type %sItem struct{", fieldType)
	def = append(def, defHead)
	for _, file := range api.Pkg.files {
		t, err := file.FindType(fieldType)
		if err != nil && strings.Contains(err.Error(), "is not found") {
			continue
		}
		//for _, field := range t.def.(*StructType).Fields() {
		//	println(field.Definition().String())
		//}
		originDef := t.Definition().String
		withoutHeadDef := strings.ReplaceAll(originDef(), "struct {", "")
		def = append(def, withoutHeadDef)
		//println(t)
	}
	return strings.Join(def, "\n")
}

func (api API) methodReqSign() string {
	var params []string
	for _, field := range api.ReqFields {
		curFieldType := field.Type
		isNeedRedefineStruct := api.isNeedRedefineStruct(field)
		if isNeedRedefineStruct {
			curFieldType = curFieldType + "Item"
		}
		params = append(params, fmt.Sprintf("%s %s", field.Alias, curFieldType))
	}
	return strings.Join(params, ",")
}

func (api API) isNeedRedefineStruct(field *ReqField) bool {
	isNeedRedefineStruct := !strings.Contains(field.Type, ".") &&
		!strings.Contains(field.Type, "map[string]") &&
		field.Type != "context.Context" &&
		field.Type != "string" &&
		field.Type != "int64" &&
		field.Type != "[]string" &&
		field.Type != "[]int64"
	return isNeedRedefineStruct
}

func (api API) genBasicAPIMethod() string {
	if len(api.Resp) == 1 {
		return "POST"
	}
	return "GET"
}

var matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
var matchAllCap = regexp.MustCompile("([a-z0-9])([A-Z])")

func ToSnakeCase(str string) string {
	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")
	return strings.ToLower(snake)
}

func upFirstChar(fieldParam string) string {
	r := []rune(fieldParam)
	return string(append([]rune{unicode.ToUpper(r[0])}, r[1:]...))
}

func lowerFirstChar(fieldParam string) string {
	r := []rune(fieldParam)
	return string(append([]rune{unicode.ToLower(r[0])}, r[1:]...))
}

type DTO struct {
	Val string
}

// camel2Case 私有方法驼峰转大写+指定分隔符
func camel2Case(name, split string) string {
	buffer := bytes.NewBufferString("")
	beforeUpper := false
	continueUpper := 0
	for i, r := range name {
		if unicode.IsUpper(r) {
			if i != 0 && !beforeUpper { //前一个字符为小写
				buffer.WriteString(split)
			}
			if i != 0 && continueUpper > 1 && i < len(name)-1 && unicode.IsLower([]rune(name)[i+1]) { //专属名称结束
				buffer.WriteString(split)
			}
			buffer.WriteRune(r)
			beforeUpper = true
			continueUpper++
		} else {
			buffer.WriteRune(unicode.ToUpper(r))
			beforeUpper = false
			continueUpper = 0
		}
	}
	return buffer.String()
}

func genReqAndResp(f *Function) *API {
	api := &API{
		Path:    f.pkg.path,
		Package: f.pkg.name,
		Method:  "",
		Req:     map[string]string{},
		Resp:    nil,
	}
	for _, parameter := range f.Func().parameters {
		val := parameter.Definition().String()
		pName := parameter.name
		//println("		param:", pName, val)
		api.Req[pName] = val
		api.ReqFields = append(api.ReqFields, &ReqField{
			Alias: pName,
			Type:  val,
		})
	}

	for _, result := range f.Func().results {
		val := result.def.String()
		api.Resp = append(api.Resp, val)
		//println("		ret:", val)
	}
	api.Method = f.name
	api.Func = f.Func()
	return api
}

func ToJSON(data interface{}) string {
	b, err := json.Marshal(data)
	if err != nil {
		println(err.Error())
	}
	return string(b)
}
func ToPrettyJSON(data interface{}) string {
	b, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		println(err.Error())
	}
	return string(b)
}

func TestName(t *testing.T) {
	println(color.InBold("This is bold"))
	println(color.InUnderline("This is underlined"))
	println(color.InBlack("This is black"))
	println(color.InRed("This is red"))
	println(color.InGreen("This is green"))
	println(color.InYellow("This is yellow"))
	println(color.InBlue("This is blue"))
	println(color.InPurple("This is purple"))
	println(color.InCyan("This is cyan"))
	println(color.InGray("This is gray"))
	println(color.InWhite("This is white"))
}
func isExported(p string) bool {
	return p[0] <= 'Z' && p[0] >= 'A'

}
