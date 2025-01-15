use cosmic::{iced::Length, widget, Element, Task};

use crate::{fl, Message};

pub struct PasswordManager {
    pub input_description: String,
    pub input_password: String,
    pub password_list: Vec<String>,
    //Which pane we should paste to, ie. which pane had focus when the
    //password manager was opened. Just to be sure it doesn't change under
    //our feet.
    pub pane: Option<widget::pane_grid::Pane>,
}

impl PasswordManager {
    pub fn new() -> Self {
        Self {
            input_description: Default::default(),
            input_password: Default::default(),
            password_list: Default::default(),
            pane: None,
        }
    }

    pub fn clear(&mut self) {
        self.input_description.clear();
        self.input_password.clear();
        self.password_list.clear();
        self.pane = None;
    }

    pub fn get_password(
        &self,
        identifier: String,
    ) -> Task<cosmic::app::message::Message<Message>> {
        if let Some(pane) = self.pane {
            cosmic::task::future(async move {
                match store::get_password(identifier.clone()).await {
                    Ok(password) => Message::Password(password, pane),
                    Err(err) => {
                        Message::Error(format!("Failed to fetch password {identifier}: {err}"))
                    }
                }
            })
            .map(cosmic::app::message::app)
        } else {
            log::error!("No active pane set for password manager to use");
            Task::none()
        }
    }

    pub fn refresh_password_list(&self) -> Task<cosmic::app::message::Message<Message>> {
        cosmic::task::future(async {
            match store::fetch_password_list().await {
                Ok(list) => Message::PasswordListRefreshed(list),
                Err(err) => Message::Error(format!("Failed to fetch password list: {err}")),
            }
        })
        .map(cosmic::app::message::app)
    }

    pub fn delete_password(
        &mut self,
        identifier: String,
    ) -> Task<cosmic::app::message::Message<Message>> {
        cosmic::task::future(async move {
            if let Err(err) = store::delete_password(identifier.clone()).await {
                return Message::Error(format!("Failed to delete password {identifier}: {err}"));
            }
            match store::fetch_password_list().await {
                Ok(list) => Message::PasswordListRefreshed(list),
                Err(err) => Message::Error(format!("Failed to fetch password list: {err}")),
            }
        })
        .map(cosmic::app::message::app)
    }

    pub fn add_inputed_password(
        &mut self,
    ) -> Task<cosmic::app::message::Message<Message>> {
        let identifier = self.input_description.clone();
        let password = self.input_password.clone();
        self.input_description.clear();
        self.input_password.clear();
        cosmic::task::future(async move {
            if let Err(err) = store::add_password(identifier.clone(), password.clone()).await {
                Message::Error(format!("Failed to add password {identifier}: {err}"))
            } else {
                Message::PasswordListRefresh()
            }
        })
        .map(cosmic::app::message::app)
    }

    pub fn context_page(&self) -> Element<Message> {
        let mut attributes = std::collections::HashMap::new();
        attributes.insert("application", "com.system76.CosmicTerm");
        let mut column = widget::list::list_column();
        for label in &self.password_list {
            column = column.add(
                widget::row()
                    .width(Length::Fill)
                    .push(
                        widget::button::text(label.clone())
                            .width(Length::Fill)
                            .on_press(Message::PasswordFetch(label.clone())),
                    )
                    .push(widget::horizontal_space())
                    .push(
                        widget::button::text("-").on_press(Message::PasswordDelete(label.clone())),
                    ),
            );
        }

        //Not really settings, but it seems this does what I want.
        let passwords_view = widget::settings::section().title(fl!("passwords")).add(column);
        let add_password_view = widget::settings::section().title(fl!("add-password"))
            .add(
                widget::text_input::text_input(
                    fl!("password-input-description"),
                    &self.input_description,
                )
                .on_input(Message::PasswordDescriptionSubmit),
            )
            .add(
                widget::text_input::text_input(fl!("password-input"), &self.input_password)
                    .on_input(Message::PasswordValueSubmit),
            )
            .add(widget::button::text("Add").on_press(Message::PasswordAdd));

        widget::settings::view_column(vec![
            passwords_view.into(),
            widget::horizontal_space().into(),
            add_password_view.into(),
        ])
        .into()
    }
}

impl Default for PasswordManager {
    fn default() -> Self {
        Self::new()
    }
}

mod store {
    use std::string::FromUtf8Error;

    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error(transparent)]
        SecretService(#[from] secret_service::Error),
        #[error(transparent)]
        FromUtf8(#[from] FromUtf8Error),
        #[error("No password found for identifier `{0}`")]
        NoPasswordForIdentifier(String),
    }

    pub async fn fetch_password_list() -> Result<Vec<String>, Error> {
        let mut list = Vec::new();
        let ss = secret_service::SecretService::connect(secret_service::EncryptionType::Dh).await?;
        let collection = ss.get_default_collection().await?;

        let mut attributes = std::collections::HashMap::new();
        attributes.insert("application", "com.system76.CosmicTerm");

        let search_items = collection.search_items(attributes).await?;

        for item in search_items {
            if let Some(identity) = item
                .get_attributes()
                .await
                .ok()
                .and_then(|attribs| attribs.get("identifier").cloned())
            {
                list.push(identity);
            }
        }
        list.sort();
        Ok(list)
    }

    pub async fn add_password(identifier: String, password: String) -> Result<(), Error> {
        let ss = secret_service::SecretService::connect(secret_service::EncryptionType::Dh).await?;
        let collection = ss.get_default_collection().await?;

        let mut attributes = std::collections::HashMap::new();
        attributes.insert("application", "com.system76.CosmicTerm");
        attributes.insert("identifier", &identifier);

        let label = format!("CosmicTerm - {}", identifier);

        collection
            .create_item(&label, attributes, password.as_bytes(), true, "text/plain")
            .await?;
        Ok(())
    }

    pub async fn get_password(identifier: String) -> Result<secstr::SecUtf8, Error> {
        let ss = secret_service::SecretService::connect(secret_service::EncryptionType::Dh).await?;
        let collection = ss.get_default_collection().await?;

        let mut attributes = std::collections::HashMap::new();
        attributes.insert("application", "com.system76.CosmicTerm");
        attributes.insert("identifier", &identifier);

        let search_items = collection.search_items(attributes).await?;
        if let Some(item) = search_items.first() {
            let secret = item.get_secret().await?;
            Ok(String::from_utf8(secret)?.into())
        } else {
            Err(Error::NoPasswordForIdentifier(identifier))
        }
    }

    pub async fn delete_password(identifier: String) -> Result<(), Error> {
        let ss = secret_service::SecretService::connect(secret_service::EncryptionType::Dh).await?;
        let collection = ss.get_default_collection().await?;

        let mut attributes = std::collections::HashMap::new();
        attributes.insert("application", "com.system76.CosmicTerm");
        attributes.insert("identifier", &identifier);

        let search_items = collection.search_items(attributes).await?;

        if let Some(item) = search_items.first() {
            Ok(item.delete().await?)
        } else {
            Err(Error::NoPasswordForIdentifier(identifier))
        }
    }
}
