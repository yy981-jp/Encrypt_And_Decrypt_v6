#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <utility>
#include <cstdio>
#include <cstdlib>
#include <qrencode.h>
#include <png.h>
#include <nlohmann/json.hpp>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtWidgets/QWidget>
#include <QtWidgets/QApplication>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStyleFactory>
#include <QtWidgets/QToolBox>
#include <QtWidgets/QPlainTextEdit>
#include <QtGui/QClipboard>
#include <QtGui/QKeyEvent>
#include <yy981/EAD_v6.h>
#include <yy981/qt/EAD_v6.h>
#include <yy981/INIParser.h>


namespace fs = std::filesystem;
Ui::EAD ui;
inline void log(const QString& i) {ui.log->setText(i);}
inline void log(const char* i) {ui.log->setText(QString::fromUtf8(i));}
inline void log(const std::string& i) {ui.log->setText(QString::fromStdString(i));}
std::string iniPath(std::string(std::getenv("localappdata")) + "/yy981/EAD_v6.ini");
std::string userDocumentDir(std::string(std::getenv("userprofile")) + "/documents");
QButtonGroup buttonGroup;
QToolBox* explanation;



void getEncrypt() {
	if (ui.en_enable_input->isChecked()) {
		if (ui.en_input->text().isEmpty() || ui.set_path_public->text().isEmpty()) {
			log("入力要素が足りません 条件: en_input set_path_public");
			return;
		}
		EAD::ER output = EAD::encryptText(ui.en_input->text().toStdString(), ui.set_path_public->text().toStdString());
		if (output.first) {
			ui.output->setText(QString::fromStdString(output.second));
			log("");
		} else log(output.second);
	} else if (ui.en_enable_path->isChecked()) {
		if (ui.en_path->text().isEmpty() || ui.set_path_public->text().isEmpty() || ui.set_path_folder->text().isEmpty()) {
			log("入力要素が足りません 条件: en_path set_path_public set_path_folder");
			return;
		}
		std::string filename = ui.en_path->text().toStdString();
		std::string outputFilename = ui.set_path_folder->text().toStdString() + "/" + fs::path(filename).filename().string() + ".enc6";
		EAD::ER output = EAD::encryptFile(filename, outputFilename, ui.set_path_public->text().toStdString());
		if (output.first) log("ファイル暗号化成功");
			else log(output.second);
	}
}

void getDecrypt() {
	if (ui.de_enable_input->isChecked()) {
		if (ui.de_input->text().isEmpty() || ui.set_path_private->text().isEmpty()) {
			log("入力要素が足りません 条件: de_input set_path_private");
			return;
		}
		EAD::ER output = EAD::decryptText(ui.de_input->text().toStdString(), ui.set_path_private->text().toStdString());
		if (output.first) ui.output->setText(QString::fromStdString(output.second)); else log(output.second);
	} else if (ui.de_enable_path->isChecked()) {
		if (ui.de_path->text().isEmpty() || ui.set_path_private->text().isEmpty() || ui.set_path_folder->text().isEmpty()) {
			log("入力要素が足りません 条件: de_path set_path_private set_path_folder");
			return;
		}
		std::string filename = ui.de_path->text().toStdString();
		std::string outputFilename = ui.set_path_folder->text().toStdString() + "/" + fs::path(filename).stem().string();
		EAD::ER output = EAD::decryptFile(filename, outputFilename, ui.set_path_private->text().toStdString());
		if (output.first) log("ファイル復号成功");
			else log(output.second);
	}
}

void getGenerateKeys() {
	if (ui.set_path_folder->text().isEmpty()) {log("入力要素が足りません 条件: set_path_folder");return;}
	int bits;
	switch (buttonGroup.checkedId()) {
		case 1: bits = 1024; break;
		case 2: bits = 2048; break;
		case 3: bits = 3072; break;
		case 4: bits = 4096; break;
		case 5: bits = 5120; break;
		case 6: bits = 6144; break;
	}
	EAD::generateKeys(ui.set_path_folder->text().toStdString() + "/" + ui.create_name->text().toStdString() + "@", bits);
}

void generateQR() {
	if (ui.qr_input->text().isEmpty() || ui.set_path_folder->text().isEmpty()) {log("入力要素が足りません 条件: qr_input set_path_folder");return;}
	if (!fs::exists("QR.exe")) {log("QR.exeが見つかりません");return;}
	std::system(std::string("QR.exe " + ui.qr_input->text().toStdString() + " " + ui.set_path_folder->text().toStdString() + "/qr.png").c_str());
    std::system(std::string("start " + ui.set_path_folder->text().toStdString() + "/qr.png").c_str());
}

void keyRead() {
	if (ui.read_path->text().isEmpty()) {log("入力要素が足りません 条件: read_path");return;}
    std::ifstream file(ui.read_path->text().toStdString());
	if (!file) {log("ファイルを開けませんでした");return;}
    std::string line;
    std::ostringstream key_content;
    int line_count = 0;

    while (std::getline(file, line)) {
        line_count++;
        if (line_count == 1 || file.peek() == EOF) {
            continue;
        }
        key_content << line;
    }

    ui.read_output->setText(QString::fromStdString(key_content.str()));
}

void keyWrite() {
	if (ui.write_path->text().isEmpty()) {log("入力要素が足りません 条件: write_path");return;}
	if (ui.write_public->isChecked()) std::ofstream(ui.write_path->text().toStdString())
		<< "-----BEGIN PUBLIC KEY-----"
		<< ui.write_input->text().toStdString()
		<< "-----END PUBLIC KEY-----";
	else std::ofstream(ui.write_path->text().toStdString())
		<< "-----BEGIN RSA PRIVATE KEY-----"
		<< ui.write_input->text().toStdString()
		<< "-----END RSA PRIVATE KEY-----";
}

void save() {
	std::string saveData[7] = {"null","null","null","null","null","null","null"};
	if (!ui.en_input->text().isEmpty()) saveData[0] = ui.en_path->text().toStdString();
	if (!ui.de_input->text().isEmpty()) saveData[1] = ui.de_path->text().toStdString();
	if (!ui.set_path_private->text().isEmpty()) saveData[2] = ui.set_path_private->text().toStdString();
	if (!ui.set_path_public->text().isEmpty()) saveData[3] = ui.set_path_public->text().toStdString();
	if (!ui.set_path_folder->text().isEmpty()) saveData[4] = ui.set_path_folder->text().toStdString();
	if (!ui.read_path->text().isEmpty()) saveData[5] = ui.read_path->text().toStdString();
	if (!ui.write_path->text().isEmpty()) saveData[6] = ui.write_path->text().toStdString();
	std::ofstream(iniPath) << "[paths]"
						  << "\nen_path = " << saveData[0]
						  << "\nde_path = " << saveData[1] 
						  << "\nset_path_private = " << saveData[2]
						  << "\nset_path_public = " << saveData[3]
						  << "\nset_path_folder = " << saveData[4]
						  << "\nread_path = " << saveData[5]
						  << "\nwrite_path = " << saveData[6]
						  << "\n[key]\nbits = " << buttonGroup.checkedId();
}

void createPage(QToolBox& explanation, std::string title, std::string content) {
    QWidget *page = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout;
	QPlainTextEdit* plaintTestEdit = new QPlainTextEdit(QString::fromStdString(content));
	plaintTestEdit->setReadOnly(true);
    layout->addWidget(plaintTestEdit);
    page->setLayout(layout);
    explanation.addItem(page, QString::fromStdString(title));
}

void jsonRead() {
	nlohmann::json jsonData;
	std::ifstream("explanation.json") >> jsonData;
	for (const auto& item : jsonData) {
        std::string name = item["name"];
        
        // contentを1つのstringにまとめる
        std::string content;
        for (const auto& line : item["content"]) {
            if (!content.empty()) {
                content += "\n";
            }
            content += line;
        }

        createPage(*explanation, name, content);
    }
}


int main(int argc, char *argv[]) {
	// qt start
    QApplication app(argc, argv);
	QWidget widget;
	ui.setupUi(&widget);
    app.setStyle(QStyleFactory::create("Fusion"));
	widget.setWindowFlags(widget.windowFlags() & ~Qt::WindowMaximizeButtonHint);
	
	// setup
	if (!fs::exists(iniPath)) {
		fs::create_directory(fs::path(iniPath).parent_path());
		std::ofstream(iniPath) << "[paths]"
							<< "\nen_path = null"
							<< "\nde_path = null"
							<< "\nset_path_private = null"
							<< "\nset_path_public = null"
							<< "\nset_path_folder = " << userDocumentDir
							<< "\nread_path = null"
							<< "\nwrite_path = null"
							<< "\n[key]\nbits = 2";
	}
	
	// explanation
	explanation = new QToolBox;
	explanation->setWindowTitle("説明画面");
	explanation->resize(700,400);
	jsonRead();
	QObject::connect(ui.other_explanation, QPushButton::clicked, []{explanation->show();});
	
	// grouper
	buttonGroup.addButton(ui.create_low,1);
	buttonGroup.addButton(ui.create_normal,2);
	buttonGroup.addButton(ui.create_high,3);
	buttonGroup.addButton(ui.create_higher,4);
	buttonGroup.addButton(ui.create_high5,5);
	buttonGroup.addButton(ui.create_high6,6);
	
	// load
	INIParser iniData(iniPath);
	if (iniData.get("paths","en_path") != "null") ui.en_path->setText(QString::fromStdString(iniData.get("paths","en_path")));
	if (iniData.get("paths","de_path") != "null") ui.de_path->setText(QString::fromStdString(iniData.get("paths","de_path")));
	if (iniData.get("paths","set_path_private") != "null") ui.set_path_private->setText(QString::fromStdString(iniData.get("paths","set_path_private")));
	if (iniData.get("paths","set_path_public") != "null") ui.set_path_public->setText(QString::fromStdString(iniData.get("paths","set_path_public")));
	if (iniData.get("paths","set_path_folder") != "null") ui.set_path_folder->setText(QString::fromStdString(iniData.get("paths","set_path_folder")));
	if (iniData.get("paths","read_path") != "null") ui.read_path->setText(QString::fromStdString(iniData.get("paths","read_path")));
	if (iniData.get("paths","write_path") != "null") ui.write_path->setText(QString::fromStdString(iniData.get("paths","write_path")));
	buttonGroup.button(std::stoi(iniData.get("key","bits")))->setChecked(true);
	
	// en_input enable control
	QObject::connect(ui.en_enable_input, &QRadioButton::toggled, []{
		if (ui.en_enable_input->isChecked()) ui.en_input->setEnabled(true); else ui.en_input->setEnabled(false);});
	QObject::connect(ui.en_enable_path, &QRadioButton::toggled, []{
		if (ui.en_enable_path->isChecked()) ui.en_path->setEnabled(true); else ui.en_path->setEnabled(false);});
	// de_input enable control
	QObject::connect(ui.de_enable_input, &QRadioButton::toggled, []{
		if (ui.de_enable_input->isChecked()) ui.de_input->setEnabled(true); else ui.de_input->setEnabled(false);});
	QObject::connect(ui.de_enable_path, &QRadioButton::toggled, []{
		if (ui.de_enable_path->isChecked()) ui.de_path->setEnabled(true); else ui.de_path->setEnabled(false);});
	
	// en de convert qr connect
	QObject::connect(ui.en_convert, &QPushButton::clicked, getEncrypt);
	QObject::connect(ui.de_convert, &QPushButton::clicked, getDecrypt);
	QObject::connect(ui.create_enter, &QPushButton::clicked, []{getGenerateKeys();save();});
	QObject::connect(ui.read_enter, &QPushButton::clicked, keyRead);
	QObject::connect(ui.write_enter, &QPushButton::clicked, keyWrite);
	
	// other
	QObject::connect(ui.other_copy, &QPushButton::clicked, [&]{
		QGuiApplication::clipboard()->setText(ui.output->text());
	});
	QObject::connect(ui.other_clear, &QPushButton::clicked, [&]{
		ui.output->setText("");
	});
	
	// save connect
	QObject::connect(ui.en_path, &QLineEdit::editingFinished, save);
	QObject::connect(ui.en_dialog, &QPushButton::clicked, [&]{
		QString temp = QFileDialog::getOpenFileName(nullptr, "ファイルを選択");
		if (temp.isEmpty()) return;
		ui.en_path->setText(temp);
		save();
	});
	QObject::connect(ui.de_path, &QLineEdit::editingFinished, save);
	QObject::connect(ui.de_dialog, &QPushButton::clicked, [&]{
		QString temp = QFileDialog::getOpenFileName(nullptr, "ENC6ファイルを選択", nullptr, "Encrypted file EncryptAndDecrypt_ver6 (*.enc6);;All files (*)");
		if (temp.isEmpty()) return;
		ui.de_path->setText(temp);
		save();
	});
	
	QObject::connect(ui.set_path_private, &QLineEdit::editingFinished, save);
	QObject::connect(ui.set_dialog_private, &QPushButton::clicked, [&]{
		QString temp = QFileDialog::getOpenFileName(nullptr, "PEMファイル(秘密鍵)を選択", nullptr, "PEM files (*.pem);;All files (*)");
		if (temp.isEmpty()) return;
		ui.set_path_private->setText(temp);
		save();
	});
	QObject::connect(ui.set_path_public, &QLineEdit::editingFinished, save);
	QObject::connect(ui.set_dialog_public, &QPushButton::clicked, [&]{
		QString temp = QFileDialog::getOpenFileName(nullptr, "PEMファイル(公開鍵)を選択", nullptr, "PEM files (*.pem);;All files (*)");
		if (temp.isEmpty()) return;
		ui.set_path_public->setText(temp);
		save();
	});
	QObject::connect(ui.set_path_folder, &QLineEdit::editingFinished, save);
	QObject::connect(ui.set_dialog_folder, &QPushButton::clicked, [&]{
		QString temp = QFileDialog::getExistingDirectory(nullptr, "フォルダを選択");
		if (temp.isEmpty()) return;
		ui.set_path_folder->setText(temp);
		save();
	});
	QObject::connect(ui.write_dialog, &QPushButton::clicked, [&]{
		QString temp = QFileDialog::getSaveFileName(nullptr, "出力PEMファイルを選択", nullptr, "PEM files (*.pem);;All files (*)");
		if (temp.isEmpty()) return;
		ui.write_path->setText(temp);
	});
	QObject::connect(ui.read_dialog, &QPushButton::clicked, [&]{
		QString temp = QFileDialog::getOpenFileName(nullptr, "入力PEMファイルを選択", nullptr, "PEM files (*.pem);;All files (*)");
		if (temp.isEmpty()) return;
		ui.read_path->setText(temp);
	});

	// go
	widget.show();
	return app.exec();
}